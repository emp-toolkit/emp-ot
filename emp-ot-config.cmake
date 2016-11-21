find_package(emp-tool)

find_path(EMP-OT_INCLUDE_DIR cmake/emp-ot-config.cmake)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(EMP-OT DEFAULT_MSG EMP-OT_INCLUDE_DIR)

if(EMP-OT_FOUND)
	set(EMP-OT_INCLUDE_DIRS ${EMP-OT_INCLUDE_DIR}/include/emp-ot/ ${EMP-TOOL_INCLUDE_DIRS})
endif()
