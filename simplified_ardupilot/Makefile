OBJ=AP_Math.o AP_AHRS.o AP_SteerController.o

all: $(OBJ)

AP_Math.o:
	g++ -std=gnu++11 -fdata-sections -ffunction-sections -fsigned-char -O3 -c AP_Math.cpp

AP_AHRS.o: AP_Math.o
	g++ -std=gnu++11 -fdata-sections -ffunction-sections -fsigned-char -O3 -c AP_AHRS.cpp

AP_SteerController.o: AP_AHRS.o
	g++ -std=gnu++11 -fdata-sections -ffunction-sections -fsigned-char -O3 -c AP_SteerController.cpp

clean:
	rm *.o
