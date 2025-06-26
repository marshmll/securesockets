CXX=clang++
INCLUDE=-I ../include
LIB=-L ../build
FLAGS=-lsecuresockets -lssl -lcrypto

all : examples

examples : blockingclient blockingserver multipleblockingclients nonblockingclient nonblockingserver multiplenonblockingclients

blockingclient : blockingclient.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

blockingserver : blockingserver.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

multipleblockingclients : multipleblockingclients.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

nonblockingclient : nonblockingclient.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

nonblockingserver : nonblockingserver.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

multiplenonblockingclients : multiplenonblockingclients.cpp
	${CXX} $^ ${INCLUDE} ${LIB} ${FLAGS} -o $@

clean:
	find . -type f -executable -exec rm -f {} \;