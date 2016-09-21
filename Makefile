OBJECTS = pcap_test.o

TARGET = pcap_test
$(TARGET) : $(OBJECTS)
	gcc -o $(TARGET) $(OBJECTS) -lpcap

pcap_test.o : pcap_test.c


