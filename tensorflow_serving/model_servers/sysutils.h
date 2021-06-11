# include <stdio.h>
# include <string.h>
void runAESCrypt(std::string,std::string,std::string);
void runAESCrypt(std::string password,std::string outputfilename,std::string inputfilename ){
    std::string s = "aescrypt -d -p "+password+" -o "+outputfilename+" "+inputfilename;
//    printf("command =%s\n", s);
//    std::cout << "Follow this command: " << s;
    system((s).c_str());
}