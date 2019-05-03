#define NAPI_VERSION 3
#include <node_api.h>

#include <stdbool.h>
#include <stdlib.h>
#include "openbsd-string.h"
#include "bcrypt.h"

enum {
	BCRYPT_MAX_KEY_LENGTH = 72,
	BCRYPT_SALT_LENGTH = 29,
};

struct hash_work_data {
	napi_async_work work;
	napi_ref callback;
	bool error;
	char password[BCRYPT_MAX_KEY_LENGTH + 1];
	char salt[BCRYPT_SALT_LENGTH + 1];
	char hash[BCRYPT_HASHSPACE];
};

static void free_unused_data(struct hash_work_data* const data) {
	explicit_bzero(data->password, BCRYPT_MAX_KEY_LENGTH);
	explicit_bzero(data->salt, BCRYPT_SALT_LENGTH);
	free(data);
}

static void hash_password_execute(napi_env const env, void* const data_) {
	struct hash_work_data* const data = data_;

	data->error = bcrypt_hashpass(data->password, data->salt, data->hash, BCRYPT_HASHSPACE) != 0;

	explicit_bzero(data->password, sizeof data->password);
	explicit_bzero(data->salt, sizeof data->salt);
}

static void check_throw(napi_status const status) {
	if (status != napi_ok && status != napi_pending_exception) {
		napi_fatal_error("bcrypt-small", NAPI_AUTO_LENGTH, "napi_throw_error failed", NAPI_AUTO_LENGTH);
	}
}

static void throw(napi_env const env, char const* const message) {
	check_throw(napi_throw_error(env, NULL, message));
}

static void hash_password_complete(napi_env const env, napi_status const status, void* const data_) {
	struct hash_work_data* const data = data_;

	napi_delete_async_work(env, data->work);

	if (status != napi_ok) {
		explicit_bzero(data->password, BCRYPT_MAX_KEY_LENGTH);
		explicit_bzero(data->salt, BCRYPT_SALT_LENGTH);
	}

	napi_value callback;

	if (napi_get_reference_value(env, data->callback, &callback) != napi_ok || callback == NULL) {
		napi_delete_reference(env, data->callback);
		explicit_bzero(data->hash, BCRYPT_HASHSPACE);
		free(data);
		throw(env, "napi_get_reference_value failed to get callback");
		return;
	}

	napi_delete_reference(env, data->callback);

	napi_value undefined;

	if (napi_get_undefined(env, &undefined) != napi_ok) {
		throw(env, "napi_get_undefined failed");
		return;
	}

	if (status != napi_ok || data->error) {
		explicit_bzero(data->hash, BCRYPT_HASHSPACE);
		free(data);

		napi_value error_message;
		napi_value argv[2];

		if (napi_create_string_utf8(env, "bcrypt failed", NAPI_AUTO_LENGTH, &error_message) != napi_ok || napi_create_error(env, NULL, error_message, &argv[0]) != napi_ok) {
			throw(env, "failed to create error");
			return;
		}

		argv[1] = undefined;

		if (napi_call_function(env, undefined, callback, 2, argv, NULL) != napi_ok) {
			throw(env, "napi_call_function failed");
			return;
		}

		return;
	}

	napi_value hash;

	napi_status const string_status = napi_create_string_utf8(env, data->hash, NAPI_AUTO_LENGTH, &hash);

	explicit_bzero(data->hash, BCRYPT_HASHSPACE);
	free(data);

	if (string_status != napi_ok) {
		throw(env, "napi_create_string_utf8 failed");
		return;
	}

	napi_value null;

	if (napi_get_null(env, &null) != napi_ok) {
		throw(env, "napi_get_null failed");
		return;
	}

	napi_value const argv[2] = {null, hash};

	if (napi_call_function(env, undefined, callback, 2, argv, NULL) != napi_ok) {
		throw(env, "napi_call_function failed");
		return;
	}
}

static napi_value hash_password(napi_env const env, napi_callback_info const cbinfo) {
	napi_value argv[3];
	size_t argc = 3;

	if (napi_get_cb_info(env, cbinfo, &argc, argv, NULL, NULL) != napi_ok) {
		throw(env, "napi_get_cb_info failed");
		return NULL;
	}

	if (argc != 3) {
		check_throw(napi_throw_type_error(env, NULL, "wrong number of arguments; expected password, salt, callback"));
		return NULL;
	}

	{
		napi_valuetype type;

		if (napi_typeof(env, argv[0], &type) != napi_ok || type != napi_string) {
			check_throw(napi_throw_type_error(env, NULL, "password must be a string"));
			return NULL;
		}

		if (napi_typeof(env, argv[1], &type) != napi_ok || type != napi_string) {
			check_throw(napi_throw_type_error(env, NULL, "salt must be a string"));
			return NULL;
		}

		if (napi_typeof(env, argv[2], &type) != napi_ok || type != napi_function) {
			check_throw(napi_throw_type_error(env, NULL, "callback must be a function"));
			return NULL;
		}
	}

	struct hash_work_data* const data = malloc(sizeof(struct hash_work_data));

	if (napi_get_value_string_utf8(env, argv[0], data->password, sizeof data->password, NULL) != napi_ok) {
		free_unused_data(data);
		throw(env, "napi_get_value_string_utf8 failed");
		return NULL;
	}

	if (napi_get_value_string_utf8(env, argv[1], data->salt, sizeof data->salt, NULL) != napi_ok) {
		free_unused_data(data);
		throw(env, "napi_get_value_string_utf8 failed");
		return NULL;
	}

	napi_value async_resource_name;

	if (napi_create_string_utf8(env, "bcrypt-small:BCRYPTREQUEST", NAPI_AUTO_LENGTH, &async_resource_name) != napi_ok) {
		free_unused_data(data);
		throw(env, "napi_create_string_utf8 failed");
		return NULL;
	}

	if (napi_create_reference(env, argv[2], 1, &data->callback) != napi_ok) {
		free_unused_data(data);
		throw(env, "napi_create_reference failed");
		return NULL;
	}

	if (napi_create_async_work(env, NULL, async_resource_name, hash_password_execute, hash_password_complete, data, &data->work) != napi_ok) {
		napi_delete_reference(env, data->callback);
		free_unused_data(data);
		throw(env, "napi_create_async_work failed");
		return NULL;
	}

	if (napi_queue_async_work(env, data->work) != napi_ok) {
		napi_delete_async_work(env, data->work);
		napi_delete_reference(env, data->callback);
		free_unused_data(data);
		throw(env, "napi_queue_async_work failed");
		return NULL;
	}

	return NULL;
}

static napi_value init(napi_env const env, napi_value const exports) {
	napi_value export;

	if (napi_create_function(env, "hashPassword", NAPI_AUTO_LENGTH, hash_password, NULL, &export) != napi_ok) {
		return NULL;
	}

	return export;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
