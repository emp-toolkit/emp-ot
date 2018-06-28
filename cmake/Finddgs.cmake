FIND_PATH(DGS_INCLUDE_DIR
  NAMES dgs
  HINTS
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
)

FIND_LIBRARY(DGS_LIBRARIES
  NAMES dgs
  HINTS
  PATH_SUFFIXES lib64 lib libs64 libs libs/Win32 libs/Win64
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw
  /opt/local
  /opt/csw
  /opt
)

MESSAGE(STATUS "DGS libs: " ${DGS_LIBRARIES} )

# Sets DGS_FOUND to TRUE if DGS_INCLUDE_DIR and DGS_LIBRARIES are set;
# errors out otherwise
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(dgs DEFAULT_MSG DGS_INCLUDE_DIR DGS_LIBRARIES)
