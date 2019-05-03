{
	"targets": [
		{
			"target_name": "bcrypt",
			"sources": ["src/bcrypt-addon.c", "src/bcrypt.c", "src/blowfish.c", "src/explicit_bzero.c"],
			"cflags_c": ["-Wno-pointer-sign"]
		}
	]
}
