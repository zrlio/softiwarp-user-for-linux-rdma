set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")

rdma_provider(siw
  siw.c
  siw_verbs.c
  siw_uverbs.c
)
