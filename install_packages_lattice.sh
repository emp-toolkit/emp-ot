# Installs packages required for emp-ot/lattice.h
if [ "$(uname)" == "Darwin" ]; then
	brew update
	brew list boost || brew install boost
	brew list eigen || brew install eigen
else
	CC=`lsb_release -rs | cut -c 1-2`
	VER=`expr $CC + 0`
	if [[ $VER -gt 15 ]]; then
		sudo apt-get install -y software-properties-common
		sudo apt-get update
		sudo apt-get install -y libboost-dev
		sudo apt-get install -y libboost-{random,timer,system}-dev
	else
		sudo apt-get install -y software-properties-common
		sudo add-apt-repository -y ppa:george-edison55/cmake-3.x
		sudo add-apt-repository -y ppa:kojoley/boost
		sudo apt-get update
		sudo apt-get install -y libboost1.58-dev
		sudo apt-get install -y libboost-{random,timer,system}-dev
	fi
	sudo apt-get install -y libeigen3-dev || echo "libeigen3-dev not found in apt. You may need to add Universe to /etc/apt/sources.list and rerun this script."
fi
