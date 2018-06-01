--
PROJ_DIR = path.getabsolute("..")
BUILD_DIR = path.join(PROJ_DIR, "build")

solution "ds1_mod_sol"
	location "build"
	
	configurations {
		"Debug",
		"Release"
	}

	platforms {
		"x32"
	}

	language "C++"
	
	flags {
		"NoExceptions",
		"NoRTTI"
	}
	
	targetdir(BUILD_DIR)
	
	-- disable exception related warnings
	buildoptions{ "/wd4577", "/wd4530" }

	
project "ds1_mod"
	kind "SharedLib"
	
	configuration {"Debug"}
		targetsuffix "_dbg"
		flags {
			"Symbols",
		}
		defines {
			"DEBUG",
			"CONF_DEBUG"
		}
	
	configuration {"Release"}
		flags {
		}
		defines {
			"NDEBUG",
			"CONF_RELEASE"
		}
	
	configuration {}
	
	files {
		"src/*.h",
		"src/*.cpp",
		"src/*.def",
	}
	
	links { 
		"user32",
	}