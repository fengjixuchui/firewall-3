#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <mutex>          
#include <unordered_map>
#include <winsock2.h>
#include <psapi.h>
#include <shlwapi.h>

#include <algorithm> 
#include <cctype>
#include <locale>

#include <conio.h>

#include "windivert.h"

using namespace std;

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define htons(x)            WinDivertHelperHtons(x)
#define htonl(x)            WinDivertHelperHtonl(x)

vector<string> split_args(string str)
{
	vector<string> tmp = {};
	string arg = "";
	for (string::size_type i = 0; i < str.size(); i++)
	{
		char c = str[i];
		if (c == '#')
		{
			break;
		}
		else if (isspace(c))
		{
			if (arg.compare("") != 0)
			{
				tmp.push_back(arg);
				arg = "";
			}
		}
		else
		{
			arg.push_back(c);
		}
	}
	if (arg.compare("") != 0)
	{
		tmp.push_back(arg);
		arg = "";
	}
	return tmp;
}

vector<string> split(string str, char del, bool skip_empty = false)
{
	vector<string> tmp = {};
	string arg = "";
	for (string::size_type i = 0; i < str.size(); i++)
	{
		char c = str[i];
		if (c == del)
		{
			if (!skip_empty || arg.compare("") != 0)
			{
				tmp.push_back(arg);
				arg = "";
			}
		}
		else
		{
			arg.push_back(c);
		}
	}
	if (!skip_empty || arg.compare("") != 0)
	{
		tmp.push_back(arg);
		arg = "";
	}
	return tmp;
}

string format(ULONG num)
{
	if (num < 1000) return to_string(num);
	if (num < 1024000) return to_string(num / 1024) + "K";
	if (num < 1048576000) return to_string(num / 1048576) + "M";
	if (num < 1073741824000) return to_string(num / 1073741824) + "G";
	if (num < 1099511627776000) return to_string(num / 1099511627776) + "T";
	return "inf";
}

string format_ip(string ip)
{
	if (ip.compare("::") == 0)
	{
		return "  0.  0.  0.  0";
	}
	else
	{
		vector<string> octets = split(ip, '.');
		if (octets.size() == 4)
		{
			octets[0].insert(0, 3 - octets[0].length(), ' ');
			octets[1].insert(0, 3 - octets[1].length(), ' ');
			octets[2].insert(0, 3 - octets[2].length(), ' ');
			octets[3].insert(0, 3 - octets[3].length(), ' ');
			return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
		}
		else
		{
			return ip;
		}
	}
}

static inline void ltrim(string & s) {
	s.erase(s.begin(), find_if(s.begin(), s.end(), [](unsigned char ch) {
		return !isspace(ch);
		}));
}

static inline void rtrim(string & s) {
	s.erase(find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
		return !isspace(ch);
		}).base(), s.end());
}

static inline void trim(string & s) {
	ltrim(s);
	rtrim(s);
}

string truncate(string str, size_t width)
{
	if (str.length() > width)
		return str.substr(0, width);
	return str;
}

bool validate_subnet(string subnet)
{
	if (subnet.compare("*") == 0) return true;

	vector<string> subnet_ = split(subnet, '/');
	vector<string> network = split(subnet_[0], '.');
	if (network.size() != 4) return false;
	int network_a, network_b, network_c, network_d;
	try
	{
		network_a = stoi(network[0]);
		network_b = stoi(network[1]);
		network_c = stoi(network[2]);
		network_d = stoi(network[3]);
	}
	catch (const std::exception&)
	{
		return false;
	}

	if (network_a < 0 || network_a > 255) return false;
	if (network_b < 0 || network_a > 255) return false;
	if (network_c < 0 || network_a > 255) return false;
	if (network_d < 0 || network_a > 255) return false;


	if (subnet_.size() == 1);
	else if (subnet_.size() == 2)
	{
		int cidr;
		try
		{
			cidr = stoi(subnet_[1]);
		}
		catch (const std::exception&)
		{
			return false;
		}
		if (cidr < 0 || cidr > 32) return false;
	}
	else return false;

	return true;
}

bool ip_match(string ip, string subnet)
{
	if (subnet.compare("*") == 0) return true;

	vector<string> ip_s = split(ip, '.');
	UINT ip_ = stoi(ip_s[0]) << 24 | stoi(ip_s[1]) << 16 | stoi(ip_s[2]) << 8 | stoi(ip_s[3]);

	vector<string> subnet_ = split(subnet, '/');
	vector<string> network = split(subnet_[0], '.');
	if (network.size() != 4) return false; //invalid
	UINT network_ = stoi(network[0]) << 24 | stoi(network[1]) << 16 | stoi(network[2]) << 8 | stoi(network[3]);
	UINT mask = 0xFFFFFFFF;
	if (subnet_.size() == 1);
	else if (subnet_.size() == 2)
		mask = mask << (32 - stoi(subnet_[1]));
	else
		return false;

	return ~(mask & (ip_ ^ network_)) == 0xFFFFFFFF;
}

#define MAXBUF 4096
#define INET6_ADDRSTRLEN 45
#define TIMEOUT 3
#define TCP_TIMEOUT 300
#define UDP_TIMEOUT 10

struct socket_state
{
	string process = "";
	string protocol = "";
	string local_ip = "";
	string local_port = "";
	string remote_ip = "";
	string remote_port = "";
	string direction = "";
	ULONG packets_in = 0;
	ULONG packets_out = 0;
	ULONG bytes_in = 0;
	ULONG bytes_out = 0;
	string status = "";
	string flags = "";
	time_t heartbeat = 0;
};

struct rule
{
	string protocol;
	string local_ip;
	string local_port;
	string remote_ip;
	string remote_port;
	string process;
	string policy;
};

struct loopback_rule
{
	string protocol;
	string client_ip;
	string client_port;
	string client_process;
	string server_ip;
	string server_port;
	string server_process;
	string policy;
};

HANDLE s_handle;
HANDLE n_handle;

vector<rule> in_rules = {};
vector<rule> out_rules = {};
vector<loopback_rule> loopback_rules = {};

list<string> sockets_order;
unordered_map<string, socket_state*> sockets = {};

unordered_map<string, string> processByPort_;
unordered_map<string, socket_state*> processUnknown;

mutex mtx_sockets;
mutex mtx_processByPort;
mutex mtx_console;

string processById(DWORD id)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, id);
	DWORD path_len = 0;
	char path[MAX_PATH + 1];
	string filename = "";
	if (process != NULL)
	{
		path_len = GetProcessImageFileNameA(process, path, sizeof(path));
		CloseHandle(process);
	}
	if (path_len != 0)
	{
		char* filename_ = PathFindFileNameA(path);
		filename = string(filename_);
	}
	else if (id == 4)
	{
		filename = "System";
	}
	else
	{
		filename = "pid=" + to_string(id);
	}

	return filename;
}

string processByPort(string protocol, string ip, string port)
{
	if (protocol.compare("UDP") == 0)
		int x = 0;

	string tuple1 = protocol + " " + ip + ":" + port;
	string tuple2 = protocol + " 0.0.0.0:" + port;

	string process = "";

	mtx_processByPort.lock();

	if (processByPort_.find(tuple1) != processByPort_.cend())
	{
		process = processByPort_[tuple1];
	}
	else if (processByPort_.find(tuple2)!= processByPort_.cend())
	{
		process = processByPort_[tuple2];
	}

	mtx_processByPort.unlock();

	return process;
}

void socket_update_status(socket_state * socket_state_, string direction, bool fin, bool syn, bool rst, bool psh, bool ack)
{
	if (socket_state_->protocol.compare("UDP") == 0)
	{
		if (socket_state_->status.compare("CNCT") == 0)
		{
			if (socket_state_->direction.compare(direction) != 0)
			{
				socket_state_->status = "EST";
			}
		}
		else if (socket_state_->status.compare("TOUT") == 0)
		{
			socket_state_->status = "EST";
		}
	}
	else if (socket_state_->protocol.compare("TCP") == 0)
	{
		if (rst)
		{
			socket_state_->status = "RST";
		}
		else if (socket_state_->status.compare("CNCT") == 0)
		{
			if (socket_state_->direction.compare(direction) != 0 && syn && ack)
			{
				socket_state_->status = "EST";
			}
		}
		else if (socket_state_->status.compare("EST") == 0)
		{
			if (fin && !ack)
			{
				if (direction.compare("->") == 0)
				{
					socket_state_->status = "LFIN";
				}
				else if (direction.compare("<-") == 0)
				{
					socket_state_->status = "RFIN";
				}
			}
		}
		else if (socket_state_->status.compare("LFIN") == 0)
		{
			if (direction.compare("<-") == 0 && fin && ack)
			{
				socket_state_->status = "CLSD";
			}
		}
		else if (socket_state_->status.compare("RFIN") == 0)
		{
			if (direction.compare("->") == 0 && fin && ack)
			{
				socket_state_->status = "CLSD";
			}
		}
		else if (socket_state_->status.compare("CLSD") == 0)
		{
			if (syn && !ack)
			{
				socket_state_->status = "CNCT";
			}
			else if (socket_state_->status.compare("TOUT") == 0)
			{
				socket_state_->status = "EST";
			}
		}
	}
}

bool process_packet(time_t now, string process, string direction,
	string protocol, string local_ip, string local_port, string remote_ip, string remote_port,
	UINT packet_len, bool fin, bool syn, bool rst, bool psh, bool ack,
	bool packet = true)
{
	string tuple = protocol + " " + local_ip + ":" + local_port + " " + remote_ip + ":" + remote_port;

	socket_state* socket_state_;

	mtx_sockets.lock();

	if (sockets.find(tuple) == sockets.cend())
	{
		bool accept = false;
		bool hide = false;

		if ((protocol.compare("TCP") == 0 && syn && !ack) || protocol.compare("UDP") == 0)
		{
			vector<rule> table;
			if (direction.compare("->") == 0)
				table = out_rules;
			else if (direction.compare("<-") == 0)
				table = in_rules;

			for (size_t i = 0; i < table.size(); i++)
			{
				rule rule = table[i];
				if (rule.process.compare("*") != 0 && rule.process.compare(process) != 0) continue;
				if (rule.protocol.compare("*") != 0 && rule.protocol.compare(protocol) != 0) continue;
				if (!ip_match(local_ip, rule.local_ip)) continue;
				if (rule.local_port.compare("*") != 0 && rule.local_port.compare(local_port) != 0) continue;
				if (!ip_match(remote_ip, rule.remote_ip)) continue;
				if (rule.remote_port.compare("*") != 0 && rule.remote_port.compare(remote_port) != 0) continue;
				if (rule.policy.compare("ACCEPT") == 0)
				{
					accept = true;
				}
				else if (rule.policy.compare("ACCEPT_HIDE") == 0)
				{
					accept = true;
					hide = true;
				}
				break;
			}
		}

		if (!accept)
		{
			mtx_sockets.unlock();
			return false;
		}

		socket_state_ = new socket_state();

		socket_state_->process = process;
		socket_state_->protocol = protocol;
		socket_state_->local_ip = local_ip;
		socket_state_->local_port = local_port;
		socket_state_->remote_ip = remote_ip;
		socket_state_->remote_port = remote_port;
		socket_state_->direction = direction;
		socket_state_->status = "CNCT";
		socket_state_->heartbeat = now;

		sockets[tuple] = socket_state_;

		if (!hide) sockets_order.push_front(tuple);
	}
	else
	{
		socket_state_ = sockets[tuple];

		socket_state_->heartbeat = now;

		socket_update_status(socket_state_, direction, fin, syn, rst, psh, ack);
	}

	if (packet)
	{
		if (direction.compare("->") == 0)
		{
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}
		else if (direction.compare("<-") == 0)
		{
			socket_state_->packets_in++;
			socket_state_->bytes_in += packet_len;
		}
	}

	list<string>::iterator i = find(sockets_order.begin(), sockets_order.end(), tuple);
	if (i != sockets_order.end())
	{
		sockets_order.erase(i);
		sockets_order.push_front(tuple);
	}

	mtx_sockets.unlock();

	return true;
}

bool process_loopback_packet(time_t now, string protocol,
	string client_ip, string client_port, string client_process,
	string server_ip, string server_port, string server_process,
	UINT packet_len, bool fin, bool syn, bool rst, bool psh, bool ack,
	bool packet = true)
{
	mtx_sockets.lock();

	string out_tuple = protocol + " " + client_ip + ":" + client_port + " " + server_ip + ":" + server_port;
	string in_tuple = protocol + " " + server_ip + ":" + server_port + " " + client_ip + ":" + client_port;

	socket_state* socket_state_;

	if (sockets.find(out_tuple) == sockets.cend())
	{
		bool accept = false;
		bool hide = false;

		if ((protocol.compare("TCP") == 0 && syn && !ack) || protocol.compare("UDP") == 0)
		{
			vector<loopback_rule> table = loopback_rules;

			for (size_t i = 0; i < table.size(); i++)
			{
				loopback_rule rule = table[i];
				if (rule.protocol.compare("*") != 0 && rule.protocol.compare(protocol) != 0) continue;
				if (!ip_match(client_ip, rule.client_ip)) continue;
				if (rule.client_port.compare("*") != 0 && rule.client_port.compare(client_port) != 0) continue;
				if (rule.client_process.compare("*") != 0 && rule.client_process.compare(client_process) != 0) continue;
				if (!ip_match(server_ip, rule.server_ip)) continue;
				if (rule.server_port.compare("*") != 0 && rule.server_port.compare(server_port) != 0) continue;
				if (rule.server_process.compare("*") != 0 && rule.server_process.compare(server_process) != 0) continue;
				if (rule.policy.compare("ACCEPT") == 0)
				{
					accept = true;
				}
				else if (rule.policy.compare("ACCEPT_HIDE") == 0)
				{
					accept = true;
					hide = true;
				}
				break;
			}
		}

		if (!accept)
		{
			mtx_sockets.unlock();
			return false;
		}

		//OUT

		socket_state_ = new socket_state();

		socket_state_->process = client_process;
		socket_state_->protocol = protocol;
		socket_state_->local_ip = client_ip;
		socket_state_->local_port = client_port;
		socket_state_->remote_ip = server_ip;
		socket_state_->remote_port = server_port;
		socket_state_->direction = "->";
		socket_state_->status = "CNCT";
		socket_state_->heartbeat = now;

		sockets[out_tuple] = socket_state_;

		if (!hide) sockets_order.push_front(out_tuple);

		if (packet)
		{
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}

		//IN

		socket_state_ = new socket_state();

		socket_state_->process = server_process;
		socket_state_->protocol = protocol;
		socket_state_->local_ip = server_ip;
		socket_state_->local_port = server_port;
		socket_state_->remote_ip = client_ip;
		socket_state_->remote_port = client_port;
		socket_state_->direction = "<-";
		socket_state_->status = "CNCT";
		socket_state_->heartbeat = now;

		sockets[in_tuple] = socket_state_;

		if (!hide) sockets_order.push_front(in_tuple);

		if (packet)
		{
			socket_state_->packets_in++;
			socket_state_->bytes_in += packet_len;
		}
	}
	else
	{
		socket_state_ = sockets[out_tuple];
		socket_state_->heartbeat = now;
		socket_update_status(socket_state_, "->", fin, syn, rst, psh, ack);

		if (packet)
		{
			socket_state_->packets_out++;
			socket_state_->bytes_out += packet_len;
		}

		if (sockets.find(in_tuple) != sockets.cend()) //just in case
		{
			socket_state_ = sockets[in_tuple];
			socket_state_->heartbeat = now;
			socket_update_status(socket_state_, "<-", fin, syn, rst, psh, ack);

			if (packet)
			{
				socket_state_->packets_in++;
				socket_state_->bytes_in += packet_len;

			}
		}
	}

	list<string>::iterator i;

	i = find(sockets_order.begin(), sockets_order.end(), out_tuple);
	if (i != sockets_order.end())
	{
		sockets_order.erase(i);
		sockets_order.push_front(out_tuple);
	}

	i = find(sockets_order.begin(), sockets_order.end(), in_tuple);
	if (i != sockets_order.end())
	{
		sockets_order.erase(i);
		sockets_order.push_front(in_tuple);
	}

	mtx_sockets.unlock();

	return true;
}

bool init()
{
	cout << "Initializing: " << endl;


	ifstream file;
	string line;
	UINT lineno;
	bool error = false;

	cout << "Loading Loopback Rules..." << endl;

	file = ifstream("loopback.txt");
	lineno = 1;
	while (getline(file, line))
	{
		vector<string> args = split_args(line);
		if (args.size() == 0);
		else if (args.size() == 8)
		{
			loopback_rule rule;
			rule.protocol = args[0];
			if (!validate_subnet(args[1]))
			{
				cout << "ERROR at line " << lineno << ": Client IP is invalid" << endl;
				error = true;
			}
			rule.client_ip = args[1];
			rule.client_port = args[2];
			rule.client_process = args[3];
			if (!validate_subnet(args[4]))
			{
				cout << "ERROR at line " << lineno << ": Server IP is invalid" << endl;
				error = true;
			}
			rule.server_ip = args[4];
			rule.server_port = args[5];
			rule.server_process = args[6];
			rule.policy = args[7];

			loopback_rules.push_back(rule);
		}
		else
		{
			cout << "ERROR at line " << lineno << ": Expected 8 arguments" << endl;
			error = true;
		}
		lineno++;
	}
	cout << "done" << endl;


	cout << "Loading Incoming Rules..." << endl;

	file = ifstream("in.txt");
	lineno = 1;
	while (getline(file, line))
	{
		vector<string> args = split_args(line);
		if (args.size() == 0);
		else if (args.size() == 7)
		{
			rule rule;
			rule.protocol = args[0];
			if (!validate_subnet(args[1]))
			{
				cout << "ERROR at line " << lineno << ": Local IP is invalid" << endl;
				error = true;
			}
			rule.local_ip = args[1];
			rule.local_port = args[2];
			if (!validate_subnet(args[3]))
			{
				cout << "ERROR at line " << lineno << ": Remote IP is invalid" << endl;
				error = true;
			}
			rule.remote_ip = args[3];
			rule.remote_port = args[4];
			rule.process = args[5];
			rule.policy = args[6];

			in_rules.push_back(rule);
		}
		else
		{
			cout << "ERROR at line " << lineno << ": Expected 7 arguments" << endl;
			error = true;
		}
		lineno++;
	}

	cout << "done" << endl;


	cout << "Loading Outgoing Rules..." << endl;

	file = ifstream("out.txt");
	lineno = 1;
	while (getline(file, line))
	{
		vector<string> args = split_args(line);
		if (args.size() == 0);
		else if (args.size() == 7)
		{
			rule rule;
			rule.protocol = args[0];
			if (!validate_subnet(args[1]))
			{
				cout << "ERROR at line " << lineno << ": Local IP is invalid" << endl;
				error = true;
			}
			rule.local_ip = args[1];
			rule.local_port = args[2];
			if (!validate_subnet(args[3]))
			{
				cout << "ERROR at line " << lineno << ": Remote IP is invalid" << endl;
				error = true;
			}
			rule.remote_ip = args[3];
			rule.remote_port = args[4];
			rule.process = args[5];
			rule.policy = args[6];

			out_rules.push_back(rule);
		}
		else
		{
			cout << "ERROR at line " << lineno << ": Expected 7 arguments" << endl;
			error = true;
		}
		lineno++;
	}

	cout << "done" << endl;

	if (error) return false;

	cout << "opening socket handle...";

	s_handle = WinDivertOpen(
		"true",
		WINDIVERT_LAYER_SOCKET, 1, WINDIVERT_FLAG_SNIFF + WINDIVERT_FLAG_READ_ONLY);
	if (s_handle == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: " << GetLastError() << endl;
		return false;
	}

	cout << "done" << endl;


	cout << "opening network handle...";

	n_handle = WinDivertOpen(
		"true",
		WINDIVERT_LAYER_NETWORK, 0, 0);
	if (n_handle == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR: " << GetLastError() << endl;
		return false;
	}

	cout << "done" << endl;


	cout << "netstat...";
	system("netstat -a -n -o > netstat.txt");
	cout << "done" << endl;

	time_t now;
	time(&now);

	cout << "parsing netstat.txt...";

	unordered_map<string, string> loopback = {};

	file = ifstream("netstat.txt");
	while (getline(file, line))
	{
		vector<string> args = split_args(line);
		string protocol = "";
		if (args.size() > 0) protocol = args[0];
		string local_ip;
		string local_port;
		string remote_ip;
		string remote_port;
		if (protocol.compare("TCP") == 0 && args.size() == 5 ||
			protocol.compare("UDP") == 0 && args.size() == 4)
		{
			vector<string> local_s = split(args[1], ':');
			if (local_s.size() != 2) continue; //possible ipv6
			local_ip = local_s[0];
			local_port = local_s[1];

			vector<string> remote_s = split(args[2], ':');
			if (remote_s.size() != 2) continue; //possible ipv6
			remote_ip = remote_s[0];
			remote_port = remote_s[1];

			DWORD processId = 0;
			string state = "";
			if (protocol.compare("TCP") == 0)
			{
				state = args[3];
				processId = stoul(args[4]);
			}
			else if (protocol.compare("UDP") == 0)
			{
				processId = stoul(args[3]);
			}

			string process = processById(processId);

			if (state.compare("") == 0 || state.compare("LISTENING") == 0)
			{
				processByPort_[protocol + " " + local_ip + ":" + local_port] = process;
			}
			else
			{
				if (local_ip.compare(remote_ip) == 0 || ip_match(local_ip, "127.0.0.1/8")) //loopback
				{
					string tuple = "";
					tuple.append(protocol);
					tuple.append(" ");
					tuple.append(local_ip);
					tuple.append(":");
					tuple.append(local_port);
					tuple.append(" ");
					tuple.append(remote_ip);
					tuple.append(":");
					tuple.append(remote_port);

					string tuple_ = "";
					tuple_.append(protocol);
					tuple_.append(" ");
					tuple_.append(remote_ip);
					tuple_.append(":");
					tuple_.append(remote_port);
					tuple_.append(" ");
					tuple_.append(local_ip);
					tuple_.append(":");
					tuple_.append(local_port);

					if (loopback.find(tuple_) == loopback.cend())
					{
						loopback[tuple] = process;
					}
					else //match
					{
						string process_ = loopback[tuple_];

						if (state.compare("ESTABLISHED") == 0 || state.compare("SYN_RECV") == 0)
						{
							if (process_loopback_packet(now, protocol,
								remote_ip, remote_port, process_,
								local_ip, local_port, process,
								0, false, true, false, false, false,
								false))
							{
								if (state.compare("ESTABLISHED") == 0)
								{
									process_loopback_packet(now, protocol,
										local_ip, local_port, process,
										remote_ip, remote_port, process_,
										0, false, true, false, false, true,
										false);
								}
							}
						}

						loopback.erase(tuple_);
					}
				}
				else
				{
					if (state.compare("SYN_SENT") == 0)
					{
						process_packet(now, process, "->",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false);
					}
					else if (state.compare("SYN_RECV") == 0)
					{
						process_packet(now, process, "<-",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false);
					}
					else if (state.compare("ESTABLISHED") == 0)
					{
						if (process_packet(now, process, "<-",
							protocol, local_ip, local_port, remote_ip, remote_port, 0,
							false, true, false, false, false,
							false))
						{
							process_packet(now, process, "->",
								protocol, local_ip, local_port, remote_ip, remote_port, 0,
								false, true, false, false, true,
								false);
						}
						else
						{
							if (process_packet(now, process, "->",
								protocol, local_ip, local_port, remote_ip, remote_port, 0,
								false, true, false, false, false,
								false))
							{
								process_packet(now, process, "<-",
									protocol, local_ip, local_port, remote_ip, remote_port, 0,
									false, true, false, false, true,
									false);
							}
						}
					}
				}
			}
		}
	}


	cout << "done" << endl;

	//for (unordered_map<string, string>::iterator i = loopback.begin(); i != loopback.cend(); i++)
	//{
	//	cout << i->first << " " << i->second << endl;
	//}

	return true;
}

void socket_()
{
	for (ULONG i = 0; ; i++)
	{
		WINDIVERT_ADDRESS addr;
		if (!WinDivertRecv(s_handle, NULL, 0, NULL, &addr))	continue;
		if (addr.IPv6) continue;

		time_t now;

		time(&now);

		string process = processById(addr.Socket.ProcessId);

		string event;
		switch (addr.Event)
		{
		case WINDIVERT_EVENT_SOCKET_BIND:
			event = "BIND";
			break;
		case WINDIVERT_EVENT_SOCKET_LISTEN:
			event = "LISTEN";
			break;
		case WINDIVERT_EVENT_SOCKET_CONNECT:
			event = "CONNECT";
			break;
		case WINDIVERT_EVENT_SOCKET_ACCEPT:
			event = "ACCEPT";
			break;
		case WINDIVERT_EVENT_SOCKET_CLOSE:
			event = "CLOSE";
			break;
		default:
			event = "";
			break;
		}

		string protocol;
		switch (addr.Socket.Protocol)
		{
		case IPPROTO_TCP:
			protocol = "TCP";
			break;
		case IPPROTO_UDP:
			protocol = "UDP";
			break;
		case IPPROTO_ICMP:
			protocol = "ICMP";
			break;
		case IPPROTO_ICMPV6:
			protocol = "ICMPV6";
			break;
		default:
			protocol = to_string(addr.Socket.Protocol);
			break;
		}

		string direction;
		if (addr.Outbound)
			direction = "->";
		else
			direction = "<-";


		char local_str[INET6_ADDRSTRLEN + 1], remote_str[INET6_ADDRSTRLEN + 1];

		WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str, sizeof(local_str));
		WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str, sizeof(remote_str));

		string local_ip = string(local_str);
		if (local_ip.compare("::") == 0) local_ip = "0.0.0.0";
		string local_port = to_string(addr.Socket.LocalPort);

		string remote_ip = string(remote_str);
		if (remote_ip.compare("::") == 0) remote_ip = "0.0.0.0";
		string remote_port = to_string(addr.Socket.RemotePort);

		if (event.compare("BIND") == 0 || (addr.Loopback && event.compare("CONNECT") == 0))
		{
			if (protocol.compare("UDP") == 0)
				int x = 0;
			
			mtx_processByPort.lock();
			processByPort_[protocol + " " + local_ip + ":" + local_port] = process;
			mtx_processByPort.unlock();
		}
	}
}

void network()
{
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packet_len;

	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];
	PVOID payload;
	UINT payload_len;

	string protocol;
	string src_ip, dst_ip;
	bool fin, syn, rst, psh, ack;
	string direction;

	string src_port, dst_port;

	time_t now;

	// Main capture-modify-inject loop:
	for (ULONG i = 0; ; i++)
	{
		if (!WinDivertRecv(n_handle, packet, sizeof(packet), &packet_len, &addr)) continue;
		
		time(&now);

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
			NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, &payload,
			&payload_len, NULL, NULL);

		if (ip_header == NULL || (tcp_header == NULL && udp_header == NULL))
		{
			continue;
		}

		WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr), src_str, sizeof(src_str));
		WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr), dst_str, sizeof(dst_str));

		src_ip = string(src_str);
		dst_ip = string(dst_str);

		fin = false;
		syn = false;
		rst = false;
		psh = false;
		ack = false;

		if (tcp_header != NULL)
		{
			protocol = "TCP";

			src_port = to_string(ntohs(tcp_header->SrcPort));
			dst_port = to_string(ntohs(tcp_header->DstPort));

			fin = tcp_header->Fin;
			syn = tcp_header->Syn;
			rst = tcp_header->Rst;
			psh = tcp_header->Psh;
			ack = tcp_header->Ack;
		}

		if (udp_header != NULL)
		{
			protocol = "UDP";
			src_port = to_string(ntohs(udp_header->SrcPort));
			dst_port = to_string(ntohs(udp_header->DstPort));
		}

		if (addr.Loopback)
		{
			if (!process_loopback_packet(now, protocol,
				src_ip, src_port, processByPort(protocol, src_ip, src_port),
				dst_ip, dst_port, processByPort(protocol, dst_ip, dst_port),
				packet_len, fin, syn, rst, psh, ack))
			{
				continue;
			}
		}
		else if (addr.Outbound)
		{
			if (!process_packet(now, processByPort(protocol, src_ip, src_port), "->",
				protocol, src_ip, src_port, dst_ip, dst_port,
				packet_len, fin, syn, rst, psh, ack))
			{
				continue;
			}
		}
		else
		{
			if (!process_packet(now, processByPort(protocol, dst_ip, dst_port), "<-",
				protocol, dst_ip, dst_port, src_ip, src_port,
				packet_len, fin, syn, rst, psh, ack))
			{
				continue;
			}
		}

		if (!WinDivertSend(n_handle, packet, packet_len, NULL, &addr)) continue;
	}
}

void heartbeat()
{
	string tuple;
	socket_state* socket_state_;
	time_t now;

	for (;;)
	{
		mtx_sockets.lock();

		time(&now);

		for (unordered_map<string, socket_state*>::iterator i = sockets.begin(); i != sockets.cend(); )
		{
			string tuple = i->first;
			socket_state_ = i->second;

			if (socket_state_->status.compare("EST") != 0 &&
				difftime(now, socket_state_->heartbeat) >= TIMEOUT)
			{
				sockets_order.remove(tuple);
				i = sockets.erase(i);
				continue;
			}

			if (socket_state_->status.compare("TOUT") != 0)
			{
				if (socket_state_->protocol.compare("UDP") == 0 && difftime(now, socket_state_->heartbeat) >= UDP_TIMEOUT ||
					socket_state_->protocol.compare("TCP") == 0 && difftime(now, socket_state_->heartbeat) >= TCP_TIMEOUT)
				{
					socket_state_->status = "TOUT";
					socket_state_->heartbeat = now;
				}
			}

			i++;
		}

		system("cls");

		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
		short rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

		mtx_console.lock();

		cout << "PRO STAT LOCAL                  REMOTE                RECV SENT IDL PROCESS" << endl;

		size_t row = 0;
		for (list<string>::iterator i = sockets_order.begin(); i != sockets_order.end(); i++)
		{
			if (row + 2 == (size_t)rows)
				break;

			string & tuple = *i;
			socket_state_ = sockets[tuple];

			ULONG idle = difftime(now, socket_state_->heartbeat);
			string idle_ = idle > 999 ? "000" : to_string(idle);

			cout
				<< left
				<< socket_state_->protocol << " "
				<< setw(4) << socket_state_->status << " "
				<< right
				<< format_ip(socket_state_->local_ip) << ":" << setw(5) << socket_state_->local_port
				<< socket_state_->direction
				<< format_ip(socket_state_->remote_ip) << ":" << setw(5) << socket_state_->remote_port << " "
				/* << setw(4) << format(socket_state_->packets_in) << " " */ << setw(4) << format(socket_state_->bytes_in) << " "
				/* << setw(4) << format(socket_state_->packets_out) << " " */ << setw(4) << format(socket_state_->bytes_out) << " "
				<< setw(3) << idle_ << " "
				<< left
				<< setw(12) << truncate(socket_state_->process, 12)
				/* << endl */;
			row++;
		}

		mtx_console.unlock();

		mtx_sockets.unlock();

		this_thread::sleep_for(chrono::seconds(1));
	}
}

int main()
{
	if (!init()) return 1;

	thread socket_(socket_);
	thread network(network);
	thread heartbeat(heartbeat);

	network.join();
}
