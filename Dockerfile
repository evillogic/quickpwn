FROM metasploitframework/metasploit-framework:6.3.47
ADD . /app
WORKDIR /app
CMD msfconsole -x "load msgrpc Pass='msf' User='msf' SSL=false ServerHost=metasploit ServerPort=55553"