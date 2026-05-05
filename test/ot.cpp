#include "test/test.h"
using namespace std;

const static int threads = 1;

int main(int argc, char** argv) {
	int length, port, party; // make sure all functions work for non-power-of-two lengths
	if (argc <= 3)
		length = (1<<20) + 101;
	else
		length = (1<<atoi(argv[3])) + 101;

	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	IKNP * iknp = new IKNP(io);
	cout <<"Passive IKNP OT\t"<<double(length)/test_ot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive IKNP COT\t"<<double(length)/test_cot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive IKNP ROT\t"<<double(length)/test_rot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive IKNP RCOT\t"<<double(length)/test_rcot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	delete iknp;

	iknp = new IKNP(io, true);
	cout <<"Active IKNP OT\t"<<double(length)/test_ot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active IKNP COT\t"<<double(length)/test_cot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active IKNP ROT\t"<<double(length)/test_rot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active IKNP RCOT\t"<<double(length)/test_rcot<IKNP>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	delete iknp;

	IOChannel* ios[1] = { io };
	FerretCOT * ferretcot = new FerretCOT(party, threads, ios, false);
	cout <<"Passive FERRET OT\t"<<double(length)/test_ot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive FERRET COT\t"<<double(length)/test_cot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive FERRET ROT\t"<<double(length)/test_rot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	delete ferretcot;
	ferretcot = new FerretCOT(party, threads, ios, true);
	cout <<"Active FERRET OT\t"<<double(length)/test_ot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active FERRET COT\t"<<double(length)/test_cot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active FERRET ROT\t"<<double(length)/test_rot<FerretCOT>(ferretcot, io, party, length)*1e6<<" OTps"<<endl;
	delete ferretcot;


	delete io;
}

