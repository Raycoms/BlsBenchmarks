# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ray/CLionProjects/blsbench2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ray/CLionProjects/blsbench2

# Include any dependencies generated for this target.
include CMakeFiles/blsbench2.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/blsbench2.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/blsbench2.dir/flags.make

CMakeFiles/blsbench2.dir/test.cpp.o: CMakeFiles/blsbench2.dir/flags.make
CMakeFiles/blsbench2.dir/test.cpp.o: test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ray/CLionProjects/blsbench2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/blsbench2.dir/test.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/blsbench2.dir/test.cpp.o -c /home/ray/CLionProjects/blsbench2/test.cpp

CMakeFiles/blsbench2.dir/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/blsbench2.dir/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ray/CLionProjects/blsbench2/test.cpp > CMakeFiles/blsbench2.dir/test.cpp.i

CMakeFiles/blsbench2.dir/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/blsbench2.dir/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ray/CLionProjects/blsbench2/test.cpp -o CMakeFiles/blsbench2.dir/test.cpp.s

# Object files for target blsbench2
blsbench2_OBJECTS = \
"CMakeFiles/blsbench2.dir/test.cpp.o"

# External object files for target blsbench2
blsbench2_EXTERNAL_OBJECTS =

blsbench2: CMakeFiles/blsbench2.dir/test.cpp.o
blsbench2: CMakeFiles/blsbench2.dir/build.make
blsbench2: CMakeFiles/blsbench2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ray/CLionProjects/blsbench2/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable blsbench2"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/blsbench2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/blsbench2.dir/build: blsbench2

.PHONY : CMakeFiles/blsbench2.dir/build

CMakeFiles/blsbench2.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/blsbench2.dir/cmake_clean.cmake
.PHONY : CMakeFiles/blsbench2.dir/clean

CMakeFiles/blsbench2.dir/depend:
	cd /home/ray/CLionProjects/blsbench2 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ray/CLionProjects/blsbench2 /home/ray/CLionProjects/blsbench2 /home/ray/CLionProjects/blsbench2 /home/ray/CLionProjects/blsbench2 /home/ray/CLionProjects/blsbench2/CMakeFiles/blsbench2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/blsbench2.dir/depend
