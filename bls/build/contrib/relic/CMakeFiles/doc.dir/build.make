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

# Utility rule file for doc.

# Include the progress variables for this target.
include contrib/relic/CMakeFiles/doc.dir/progress.make

contrib/relic/CMakeFiles/doc:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic && /usr/bin/doxygen /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic/doc/relic.doxygen

doc: contrib/relic/CMakeFiles/doc
doc: contrib/relic/CMakeFiles/doc.dir/build.make

.PHONY : doc

# Rule to build all files generated by this target.
contrib/relic/CMakeFiles/doc.dir/build: doc

.PHONY : contrib/relic/CMakeFiles/doc.dir/build

contrib/relic/CMakeFiles/doc.dir/clean:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic && $(CMAKE_COMMAND) -P CMakeFiles/doc.dir/cmake_clean.cmake
.PHONY : contrib/relic/CMakeFiles/doc.dir/clean

contrib/relic/CMakeFiles/doc.dir/depend:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ray/Documents/IdeaProjects/bls-signatures /home/ray/Documents/IdeaProjects/bls-signatures/contrib/relic /home/ray/Documents/IdeaProjects/bls-signatures/build /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic /home/ray/Documents/IdeaProjects/bls-signatures/build/contrib/relic/CMakeFiles/doc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : contrib/relic/CMakeFiles/doc.dir/depend
