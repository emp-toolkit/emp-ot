FIND_PATH(DGS_INCLUDE_DIR RR.h
  HINTS
  $ENV{NTLDIR}
  PATH_SUFFIXES NTL include/NTL include
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw # Fink
  /opt/local # DarwinPorts
  /opt/csw # Blastwave
  /opt
)

FIND_LIBRARY(DGS_LIBRARIES
  NAMES dgs
  HINTS
  $ENV{NTLDIR}
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

# handle the QUIETLY and REQUIRED arguments and set NTL_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NTL DEFAULT_MSG  NTL_LIBRARIES NTL_INCLUDE_DIR)

MARK_AS_ADVANCED(NTL_LIBRARIES NTL_INCLUDE_DIR)
