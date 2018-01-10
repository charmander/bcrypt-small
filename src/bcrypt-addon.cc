#include <node.h>
#include <uv.h>
#include <cstring>

extern "C" {
	#include "openbsd-string.h"
	#include "bcrypt.h"
}

namespace {
	size_t constexpr BCRYPT_MAX_KEY_LENGTH = 72;
	size_t constexpr BCRYPT_SALT_LENGTH = 29;

	class HashWork {
	public:
		v8::Persistent<v8::Function> callback;
		bool error;
		char password[BCRYPT_MAX_KEY_LENGTH + 1];
		char salt[BCRYPT_SALT_LENGTH + 1];
		char hash[BCRYPT_HASHSPACE];
	};

	void hash_password(uv_work_t* const request) {
		HashWork* const work = static_cast<HashWork*>(request->data);

		work->error = bcrypt_hashpass(work->password, work->salt, work->hash, BCRYPT_HASHSPACE) != 0;

		explicit_bzero(work->password, sizeof work->password);
		explicit_bzero(work->salt, sizeof work->salt);
	}

	void hash_password_done(uv_work_t* const request, int const status) {
		HashWork* const work = static_cast<HashWork*>(request->data);

		v8::Isolate* const isolate = v8::Isolate::GetCurrent();
		v8::HandleScope scope(isolate);

		v8::Local<v8::Value> callback_args[2];

		if (work->error) {
			callback_args[0] = v8::Exception::Error(
				v8::String::NewFromUtf8(isolate, "bcrypt failed"));
			callback_args[1] = v8::Null(isolate);
		} else {
			callback_args[0] = v8::Null(isolate);
			callback_args[1] = v8::String::NewFromUtf8(isolate, work->hash);
		}

		v8::Local<v8::Function>::New(isolate, work->callback)
			->Call(isolate->GetCurrentContext()->Global(), 2, callback_args);

		work->callback.Reset();

		explicit_bzero(work->hash, BCRYPT_HASHSPACE);
		delete work;
		delete request;
	}

	void hash_password_async(v8::FunctionCallbackInfo<v8::Value> const& args) {
		v8::Isolate* const isolate = args.GetIsolate();

		if (args.Length() != 3) {
			isolate->ThrowException(v8::Exception::TypeError(
				v8::String::NewFromUtf8(isolate, "wrong number of arguments; expected password, salt, callback")));
			return;
		}

		if (!args[0]->IsString()) {
			isolate->ThrowException(v8::Exception::TypeError(
				v8::String::NewFromUtf8(isolate, "password must be a string")));
			return;
		}

		if (!args[1]->IsString()) {
			isolate->ThrowException(v8::Exception::TypeError(
				v8::String::NewFromUtf8(isolate, "salt must be a string")));
			return;
		}

		if (!args[2]->IsFunction()) {
			isolate->ThrowException(v8::Exception::TypeError(
				v8::String::NewFromUtf8(isolate, "callback must be a function")));
			return;
		}

		v8::Local<v8::String> const password = args[0]->ToString(isolate);
		v8::Local<v8::String> const salt = args[1]->ToString(isolate);
		v8::Local<v8::Function> const callback = v8::Local<v8::Function>::Cast(args[2]);

		HashWork* const work = new HashWork();
		work->callback.Reset(isolate, callback);
		strncpy(work->password, *v8::String::Utf8Value(password), sizeof work->password - 1);
		work->password[sizeof work->password - 1] = '\0';
		strncpy(work->salt, *v8::String::Utf8Value(salt), sizeof work->salt - 1);
		work->salt[sizeof work->salt - 1] = '\0';

		uv_work_t* const request = new uv_work_t();
		request->data = work;

		uv_queue_work(
			uv_default_loop(),
			request,
			hash_password,
			hash_password_done
		);
	}

	void init(v8::Local<v8::Object> exports) {
		NODE_SET_METHOD(exports, "hashPasswordAsync", hash_password_async);
	}

	NODE_MODULE(bcrypt, init)
}
