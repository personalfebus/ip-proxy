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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/personalfebus/ip-proxy

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/personalfebus/ip-proxy

# Include any dependencies generated for this target.
include client/CMakeFiles/proxy.dir/depend.make

# Include the progress variables for this target.
include client/CMakeFiles/proxy.dir/progress.make

# Include the compile flags for this target's objects.
include client/CMakeFiles/proxy.dir/flags.make

client/CMakeFiles/proxy.dir/main.cpp.o: client/CMakeFiles/proxy.dir/flags.make
client/CMakeFiles/proxy.dir/main.cpp.o: client/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/personalfebus/ip-proxy/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object client/CMakeFiles/proxy.dir/main.cpp.o"
	cd /home/personalfebus/ip-proxy/client && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/proxy.dir/main.cpp.o -c /home/personalfebus/ip-proxy/client/main.cpp

client/CMakeFiles/proxy.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/proxy.dir/main.cpp.i"
	cd /home/personalfebus/ip-proxy/client && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/personalfebus/ip-proxy/client/main.cpp > CMakeFiles/proxy.dir/main.cpp.i

client/CMakeFiles/proxy.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/proxy.dir/main.cpp.s"
	cd /home/personalfebus/ip-proxy/client && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/personalfebus/ip-proxy/client/main.cpp -o CMakeFiles/proxy.dir/main.cpp.s

# Object files for target proxy
proxy_OBJECTS = \
"CMakeFiles/proxy.dir/main.cpp.o"

# External object files for target proxy
proxy_EXTERNAL_OBJECTS =

client/proxy: client/CMakeFiles/proxy.dir/main.cpp.o
client/proxy: client/CMakeFiles/proxy.dir/build.make
client/proxy: /usr/lib/x86_64-linux-gnu/libnetfilter_queue.so
client/proxy: client/CMakeFiles/proxy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/personalfebus/ip-proxy/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable proxy"
	cd /home/personalfebus/ip-proxy/client && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/proxy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
client/CMakeFiles/proxy.dir/build: client/proxy

.PHONY : client/CMakeFiles/proxy.dir/build

client/CMakeFiles/proxy.dir/clean:
	cd /home/personalfebus/ip-proxy/client && $(CMAKE_COMMAND) -P CMakeFiles/proxy.dir/cmake_clean.cmake
.PHONY : client/CMakeFiles/proxy.dir/clean

client/CMakeFiles/proxy.dir/depend:
	cd /home/personalfebus/ip-proxy && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/personalfebus/ip-proxy /home/personalfebus/ip-proxy/client /home/personalfebus/ip-proxy /home/personalfebus/ip-proxy/client /home/personalfebus/ip-proxy/client/CMakeFiles/proxy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : client/CMakeFiles/proxy.dir/depend

