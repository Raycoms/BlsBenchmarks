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
include python-bindings/CMakeFiles/blspy.dir/depend.make

# Include the progress variables for this target.
include python-bindings/CMakeFiles/blspy.dir/progress.make

# Include the compile flags for this target's objects.
include python-bindings/CMakeFiles/blspy.dir/flags.make

python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.o: python-bindings/CMakeFiles/blspy.dir/flags.make
python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.o: ../python-bindings/pythonbindings.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ray/Documents/IdeaProjects/bls-signatures/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.o"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/blspy.dir/pythonbindings.cpp.o -c /home/ray/Documents/IdeaProjects/bls-signatures/python-bindings/pythonbindings.cpp

python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/blspy.dir/pythonbindings.cpp.i"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ray/Documents/IdeaProjects/bls-signatures/python-bindings/pythonbindings.cpp > CMakeFiles/blspy.dir/pythonbindings.cpp.i

python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/blspy.dir/pythonbindings.cpp.s"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ray/Documents/IdeaProjects/bls-signatures/python-bindings/pythonbindings.cpp -o CMakeFiles/blspy.dir/pythonbindings.cpp.s

# Object files for target blspy
blspy_OBJECTS = \
"CMakeFiles/blspy.dir/pythonbindings.cpp.o"

# External object files for target blspy
blspy_EXTERNAL_OBJECTS =

python-bindings/blspy.cpython-38-x86_64-linux-gnu.so: python-bindings/CMakeFiles/blspy.dir/pythonbindings.cpp.o
python-bindings/blspy.cpython-38-x86_64-linux-gnu.so: python-bindings/CMakeFiles/blspy.dir/build.make
python-bindings/blspy.cpython-38-x86_64-linux-gnu.so: src/libblstmp.a
python-bindings/blspy.cpython-38-x86_64-linux-gnu.so: contrib/relic/lib/librelic_s.a
python-bindings/blspy.cpython-38-x86_64-linux-gnu.so: python-bindings/CMakeFiles/blspy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ray/Documents/IdeaProjects/bls-signatures/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared module blspy.cpython-38-x86_64-linux-gnu.so"
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/blspy.dir/link.txt --verbose=$(VERBOSE)
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && /usr/bin/strip /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings/blspy.cpython-38-x86_64-linux-gnu.so

# Rule to build all files generated by this target.
python-bindings/CMakeFiles/blspy.dir/build: python-bindings/blspy.cpython-38-x86_64-linux-gnu.so

.PHONY : python-bindings/CMakeFiles/blspy.dir/build

python-bindings/CMakeFiles/blspy.dir/clean:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings && $(CMAKE_COMMAND) -P CMakeFiles/blspy.dir/cmake_clean.cmake
.PHONY : python-bindings/CMakeFiles/blspy.dir/clean

python-bindings/CMakeFiles/blspy.dir/depend:
	cd /home/ray/Documents/IdeaProjects/bls-signatures/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ray/Documents/IdeaProjects/bls-signatures /home/ray/Documents/IdeaProjects/bls-signatures/python-bindings /home/ray/Documents/IdeaProjects/bls-signatures/build /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings /home/ray/Documents/IdeaProjects/bls-signatures/build/python-bindings/CMakeFiles/blspy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : python-bindings/CMakeFiles/blspy.dir/depend

