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
CMAKE_SOURCE_DIR = /home/ray/Documents/IdeaProjects/bls-signatures

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ray/Documents/IdeaProjects/bls-signatures/build

# Include any dependencies generated for this target.
include src/CMakeFiles/runbench.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/runbench.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/runbench.dir/flags.make

src/CMakeFiles/runbench.dir/test-bench.cpp.o: src/CMakeFiles/runbench.dir/flags.make
src/CMakeFiles/runbench.dir/test-bench.cpp.o: ../src/test-bench.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ray/Documents/IdeaProjects/bls-signatures/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/runbench.dir/test-bench.cpp.o"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/runbench.dir/test-bench.cpp.o -c /home/ray/Documents/IdeaProjects/bls-signatures/src/test-bench.cpp

src/CMakeFiles/runbench.dir/test-bench.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/runbench.dir/test-bench.cpp.i"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ray/Documents/IdeaProjects/bls-signatures/src/test-bench.cpp > CMakeFiles/runbench.dir/test-bench.cpp.i

src/CMakeFiles/runbench.dir/test-bench.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/runbench.dir/test-bench.cpp.s"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ray/Documents/IdeaProjects/bls-signatures/src/test-bench.cpp -o CMakeFiles/runbench.dir/test-bench.cpp.s

# Object files for target runbench
runbench_OBJECTS = \
"CMakeFiles/runbench.dir/test-bench.cpp.o"

# External object files for target runbench
runbench_EXTERNAL_OBJECTS =

src/runbench: src/CMakeFiles/runbench.dir/test-bench.cpp.o
src/runbench: src/CMakeFiles/runbench.dir/build.make
src/runbench: src/libblstmp.a
src/runbench: contrib/relic/lib/librelic_s.a
src/runbench: src/CMakeFiles/runbench.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ray/Documents/IdeaProjects/bls-signatures/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable runbench"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/runbench.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/runbench.dir/build: src/runbench

.PHONY : src/CMakeFiles/runbench.dir/build

src/CMakeFiles/runbench.dir/clean:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && $(CMAKE_COMMAND) -P CMakeFiles/runbench.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/runbench.dir/clean

src/CMakeFiles/runbench.dir/depend:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ray/Documents/IdeaProjects/bls-signatures /home/ray/Documents/IdeaProjects/bls-signatures/src /home/ray/Documents/IdeaProjects/bls-signatures/build /home/ray/Documents/IdeaProjects/bls-signatures/build/src /home/ray/Documents/IdeaProjects/bls-signatures/build/src/CMakeFiles/runbench.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/runbench.dir/depend

