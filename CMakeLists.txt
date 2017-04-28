cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-scripts)
include(ds_sys)
include(generic)

add_executable(dnsbalancer
	context.c
	dns.c
	evloop.c
	handlers.c
	ini.c
	main.c
	pfcq.c
	rb.c
	signals.c
	utils.c
	worker.c)

target_link_libraries(dnsbalancer
	pthread
	rt
	${LIBLDNS_LIBRARIES}
	${LIBUNWIND_LIBRARIES}
	${LIBINI_CONFIG_LIBRARIES}
	${LIBATOMIC_OPS_LIBRARIES}
	${GB_LD_EXTRA})

install(TARGETS dnsbalancer
	RUNTIME DESTINATION bin)

