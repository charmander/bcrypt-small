#include <node.h>
#include <uv.h>
#include <cstring>
#include <cstdlib>

extern "C" {
	#include "openbsd-string.h"
	#include "bcrypt.h"
}

namespace {
	struct HashWork {
		v8::Persistent<v8::Function> callback;
		char* password;
		char* salt;
		char* hash;
		int error;
	};

	void hash_password(uv_work_t* request) {
		HashWork* work = static_cast<HashWork*>(request->data);

		work->error = bcrypt_hashpass(work->password, work->salt, work->hash, BCRYPT_HASHSPACE) != 0;

		explicit_bzero(work->password, strlen(work->password));
		explicit_bzero(work->salt, strlen(work->salt));
		free(work->password);
		free(work->salt);
	}

	void hash_password_done(uv_work_t* request, int status) {
		HashWork* work = static_cast<HashWork*>(request->data);

		v8::Isolate* isolate = v8::Isolate::GetCurrent();
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
		delete[] work->hash;
		delete work;
	}

	void hash_password_async(const v8::FunctionCallbackInfo<v8::Value>& args) {
		v8::Isolate* isolate = args.GetIsolate();

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

		v8::Local<v8::String> password = args[0]->ToString(isolate);
		v8::Local<v8::String> salt = args[1]->ToString(isolate);
		v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(args[2]);

		HashWork* work = new HashWork();
		work->password = strdup(*v8::String::Utf8Value(password));
		work->salt = strdup(*v8::String::Utf8Value(salt));
		work->callback.Reset(isolate, callback);
		work->hash = new char[BCRYPT_HASHSPACE];

		uv_work_t* request = new uv_work_t();
		request->data = work;

		uv_queue_work(
			uv_default_loop(),
			request,
			hash_password,
			hash_password_done
		);

		args.GetReturnValue().Set(v8::Undefined(isolate));
	}

	void init(v8::Local<v8::Object> exports) {
		NODE_SET_METHOD(exports, "hashPasswordAsync", hash_password_async);
	}

	NODE_MODULE(bcrypt, init)
}
