CC = gcc
CFLAGS = -O2 -I.
CXX = g++
CXX_FLAGS = -O2 --std=c++17 -I.
CXX_LIBS = -lthrift -lsodium

########################################

THRIFT_PATH = gen-cpp
_THRIFT_OBJS = service_types.o SimpleAnonCredService.o
THRIFT_OBJS = $(foreach n, $(_THRIFT_OBJS), $(THRIFT_PATH)/$(n))

########################################

CURVE_PATH = src/crypto/curve
VOPRF_PATH = src/crypto/voprf
KDF_PATH = src/crypto/kdf
DLEQPROOF_PATH = src/crypto/dleqproof

_CURVE_OBJS = curve_ristretto.o
_VOPRF_OBJS = voprf_mul_twohashdh.o voprf_twohashdh.o
_KDF_OBJS = kdf_sdhi.o
_DLEQPROOF_OBJS = dleqproof.o


CRYPTO_OBJS = $(foreach n, $(_CURVE_OBJS), $(CURVE_PATH)/$(n)) \
				$(foreach n, $(_VOPRF_OBJS), $(VOPRF_PATH)/$(n)) \
				$(foreach n, $(_KDF_OBJS), $(KDF_PATH)/$(n)) \
				$(foreach n, $(_DLEQPROOF_OBJS), $(DLEQPROOF_PATH)/$(n))

########################################

SERVER_PATH = src/service
_SERVER_OBJS = SimpleAnonCredServiceHandler.o
SERVER_OBJS = $(foreach n, $(_SERVER_OBJS), $(SERVER_PATH)/$(n))
SERVER_TARGET = server

CLIENT_PATH = src/service
_CLIENT_OBJS = SimpleAnonCredClient.o
CLIENT_OBJS = $(foreach n, $(_CLIENT_OBJS), $(CLIENT_PATH)/$(n))
CLIENT_TARGET = client

UTIL_PATH = src/service
_UTIL_OBJS = SimpleAnonCredUtils.o
UTIL_OBJS = $(foreach n, $(_UTIL_OBJS), $(UTIL_PATH)/$(n))

########################################

TEST_PATH = tests
_TEST_SOURCES = dleqproof_test.cpp kdf_test.cpp voprf_test.cpp
TEST_SOURCES = $(foreach n, $(_TEST_SOURCES), $(TEST_PATH)/$(n))
TEST_TARGETS = $(TEST_SOURCES:.cpp=)

########################################

all: thrift $(SERVER_TARGET) $(CLIENT_TARGET)

tests: $(TEST_TARGETS)

thrift: service.thrift
	thrift --gen cpp $<

$(SERVER_TARGET): $(CRYPTO_OBJS) $(THRIFT_OBJS) $(UTIL_OBJS) $(SERVER_OBJS) $(SERVER_PATH)/SimpleAnonCredServer.cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@ $(CXX_LIBS)

$(CLIENT_TARGET): $(CRYPTO_OBJS) $(THRIFT_OBJS) $(UTIL_OBJS) $(CLIENT_OBJS) $(CLIENT_PATH)/SimpleAnonCredClientDemo.cpp
	$(CXX) $(CXX_FLAGS) $^ -o $@ $(CXX_LIBS)

$(CURVE_PATH)/%.o: $(CURVE_PATH)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(VOPRF_PATH)/%.o: $(VOPRF_PATH)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(KDF_PATH)/%.o: $(KDF_PATH)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(DLEQPROOF_PATH)/%.o: $(DLEQPROOF_PATH)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXX_FLAGS) -c -o $@  $<

$(TEST_PATH)/%: $(TEST_PATH)/%.cpp $(CRYPTO_OBJS)
	$(CXX) $(CXX_FLAGS) $^ -o $@ $(CXX_LIBS)

.PHONY: clean tests
clean:
	rm -f $(CRYPTO_OBJS) $(THRIFT_OBJS)
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS) $(UTIL_OBJS)
	rm -f $(TEST_TARGETS)
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)
	rm -rf $(THRIFT_PATH)
