# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/julen/julen/brokel/research/openfhe-personal

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/julen/julen/brokel/research/openfhe-personal/build

# Include any dependencies generated for this target.
include CMakeFiles/prueba-bgv.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/prueba-bgv.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/prueba-bgv.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/prueba-bgv.dir/flags.make

CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o: CMakeFiles/prueba-bgv.dir/flags.make
CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o: ../prueba-bgv.cpp
CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o: CMakeFiles/prueba-bgv.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/julen/julen/brokel/research/openfhe-personal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o -MF CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o.d -o CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o -c /home/julen/julen/brokel/research/openfhe-personal/prueba-bgv.cpp

CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/julen/julen/brokel/research/openfhe-personal/prueba-bgv.cpp > CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.i

CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/julen/julen/brokel/research/openfhe-personal/prueba-bgv.cpp -o CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.s

# Object files for target prueba-bgv
prueba__bgv_OBJECTS = \
"CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o"

# External object files for target prueba-bgv
prueba__bgv_EXTERNAL_OBJECTS =

prueba-bgv: CMakeFiles/prueba-bgv.dir/prueba-bgv.cpp.o
prueba-bgv: CMakeFiles/prueba-bgv.dir/build.make
prueba-bgv: /usr/local/lib/libOPENFHEpke.so.1.0.0
prueba-bgv: /usr/local/lib/libOPENFHEbinfhe.so.1.0.0
prueba-bgv: /usr/local/lib/libOPENFHEcore.so.1.0.0
prueba-bgv: CMakeFiles/prueba-bgv.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/julen/julen/brokel/research/openfhe-personal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable prueba-bgv"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/prueba-bgv.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/prueba-bgv.dir/build: prueba-bgv
.PHONY : CMakeFiles/prueba-bgv.dir/build

CMakeFiles/prueba-bgv.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/prueba-bgv.dir/cmake_clean.cmake
.PHONY : CMakeFiles/prueba-bgv.dir/clean

CMakeFiles/prueba-bgv.dir/depend:
	cd /home/julen/julen/brokel/research/openfhe-personal/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/julen/julen/brokel/research/openfhe-personal /home/julen/julen/brokel/research/openfhe-personal /home/julen/julen/brokel/research/openfhe-personal/build /home/julen/julen/brokel/research/openfhe-personal/build /home/julen/julen/brokel/research/openfhe-personal/build/CMakeFiles/prueba-bgv.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/prueba-bgv.dir/depend

