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

# Utility rule file for combined_custom.

# Include the progress variables for this target.
include src/CMakeFiles/combined_custom.dir/progress.make

src/CMakeFiles/combined_custom: src/libblstmp.a
src/CMakeFiles/combined_custom: contrib/relic/lib/librelic_s.a
	mkdir object_blstmp || true && cd object_blstmp && /usr/bin/ar -x /home/ray/Documents/IdeaProjects/bls-signatures/build/src/libblstmp.a
	mkdir object_relic_s || true && cd object_relic_s && /usr/bin/ar -x /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic/lib/librelic_s.a
	/usr/bin/ar -rs /home/ray/Documents/IdeaProjects/bls-signatures/build/libbls.a object_*/*.o

combined_custom: src/CMakeFiles/combined_custom
combined_custom: src/CMakeFiles/combined_custom.dir/build.make

.PHONY : combined_custom

# Rule to build all files generated by this target.
src/CMakeFiles/combined_custom.dir/build: combined_custom

.PHONY : src/CMakeFiles/combined_custom.dir/build

src/CMakeFiles/combined_custom.dir/clean:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/src && $(CMAKE_COMMAND) -P CMakeFiles/combined_custom.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/combined_custom.dir/clean

src/CMakeFiles/combined_custom.dir/depend:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ray/Documents/IdeaProjects/bls-signatures /home/ray/Documents/IdeaProjects/bls-signatures/src /home/ray/Documents/IdeaProjects/bls-signatures/build /home/ray/Documents/IdeaProjects/bls-signatures/build/src /home/ray/Documents/IdeaProjects/bls-signatures/build/src/CMakeFiles/combined_custom.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/combined_custom.dir/depend
