if(ENABLE_TESTING)
  add_subdirectory(tests)
endif()

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/mutator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crossover.c
  DESTINATION ${CMAKE_LUADIR}/mutator/
)
