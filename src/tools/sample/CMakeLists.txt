# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicsample sample.cpp)

target_link_libraries(quicsample inc warnings OpenSSL inc)
