function(IonicAppVersion)
	message("Setting IONICTOOLS_APP_VERSION")
	if(DEFINED ENV{IONIC_BUILD_APP_VERSION})
		message("IONIC_BUILD_APP_VERSION defined as: $ENV{IONIC_BUILD_APP_VERSION}")
		set (IONICTOOLS_APP_VERSION \"$ENV{IONIC_BUILD_APP_VERSION}\")
	else()
		find_package (Git)
		if (GIT_FOUND)
			message("git found: ${GIT_EXECUTABLE} in version ${GIT_VERSION_STRING}")
			execute_process(
				COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
				RESULT_VARIABLE RESULT
				OUTPUT_VARIABLE OUTPUT)
			string (STRIP ${OUTPUT} OUTPUT)
			set (IONICTOOLS_APP_VERSION \"${OUTPUT}\")
		else ()
			set (IONICTOOLS_APP_VERSION \"\")
		endif (GIT_FOUND)
	endif()
	configure_file ("include/version.h.in" "include/version.h")
endfunction(IonicAppVersion)

