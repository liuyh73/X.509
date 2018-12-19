#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <map>
using namespace std;
struct info {
    bool ismallc;
    int length;
    unsigned char* data;
};

vector<info>certInfo;
map<string, string>mapp{
    {"2.5.4.3", "CN"},
    {"1.2.840.10040.4.1", "DSA"},
    {"1.2.840.10040.4.3" , "sha1DSA"},
    {"1.2.840.113549.1.1.1" ,"RSA"},
    {"1.2.840.113549.1.1.2" , "md2RSA"},
    {"1.2.840.113549.1.1.3" , "md4RSA"},
    {"1.2.840.113549.1.1.4" , "md5RSA"},
    {"1.2.840.113549.1.1.5" , "sha1RSA"},
    {"1.3.14.3.2.29", "sha1RSA"},
    {"1.2.840.113549.1.1.13", "sha512RSA"},
    {"1.2.840.113549.1.1.11","sha256RSA"}
};
int getLength(ifstream& file, int len) {
    if (len <= 0x7F) {
        return len;
    }
    int lengthOflen = len ^ 0x80;
    unsigned char* bytes = new unsigned char[lengthOflen];
    file.read((char*)bytes, lengthOflen);
    int length = 0;
    for(int i=0; i<lengthOflen; i++){
        length = (length << 8) + int(bytes[i]);
    }
    delete []bytes;
    return length;
}

int getCertLength(ifstream& file){
    unsigned char* bytes = new unsigned char[2];
    file.read((char*)bytes, 2);
    int len = (int)bytes[1];
    delete []bytes;
    return getLength(file, len);
}

int getCertificateLength(ifstream& file){
    printf("The certificate length: %d bytes\n", getCertLength(file));
}

int getTBSCertificateLength(ifstream& file) {
    printf("The tbsCertificate length: %d bytes\n", getCertLength(file));
}

void getInfo(ifstream& file, unsigned char type, int length) {
    unsigned char* bytes = new unsigned char[length+1];
    int temp = 0, count = 0;
    string oidStr = "";
    char oidch[20];
    switch(type) {
        case 0x01:
            file.read((char*)bytes, length);
            certInfo.push_back(info{
                ismallc: false,
                length: length,
                data: (unsigned char *)(bytes[0] == 0xff ? "true" : "flase")
            });
            break;
        case 0x02:
            file.read((char*)bytes, length);
            bytes[length]='\0';
            certInfo.push_back(info{
                ismallc: true,
                length: length,
                data: bytes
            });
            break;
        case 0x03:
        case 0x04:
        case 0x13:
        case 0x17:
        case 0x18:
            file.read((char*)bytes, length);
            bytes[length]='\0';
            certInfo.push_back(info{
                ismallc: true,
                length: length,
                data: bytes
            });
            break;
        case 0x06:
            file.read((char *)bytes, length);
            for(int i=0;i<length;i++){
                if(bytes[i] & 0x80) {
                    temp = (temp << 7) + (bytes[i]^0x80);
                    continue;
                }
                temp = (temp << 7) + bytes[i];
                bytes[count] = temp;
                count+=1;
                temp = 0;
            }
            oidStr="";
            for(int i=0;i<count;i++){
                temp = (temp<<7) + bytes[i];
                memset(oidch, 0, sizeof(oidch));
                if(i==0){
                    snprintf(oidch, 20, "%d.%d.", temp/40, temp%40);
                    oidStr += oidch;
                    temp = 0;
                } else if(bytes[i] < 0x7F) {
                    snprintf(oidch, 20, "%d.", temp);
                    oidStr +=oidch;
                    temp = 0;
                }
            }
            oidStr.pop_back();
            certInfo.push_back(info{
                ismallc: false,
                length: (int)oidStr.size(),
                data: (unsigned char*)(mapp[oidStr] == "" ? oidStr.c_str() : mapp[oidStr].c_str())
            });
            delete []bytes;
            break;
        case 0xA0:
        case 0xA3:
        case 0x07:
        case 0x30:
        case 0x31:
        default:
            delete []bytes;
            break;
    }
}

string formatDate(info &inf) {
    string datetime = "";
    if(inf.length < 0x12) {
        datetime = datetime+"20"+(char)inf.data[0]+(char)inf.data[1] + "-" +(char)inf.data[2]+(char)inf.data[3]+"-"+(char)inf.data[4]+(char)inf.data[5];
        datetime = datetime + " "+(char)inf.data[6]+(char)inf.data[7]+":"+(char)inf.data[8]+(char)inf.data[9]+":"+(char)inf.data[10]+(char)inf.data[11]+(char)inf.data[12];
        if(inf.data[13] != '\0') {
            datetime = datetime + (char)inf.data[13]+(char)inf.data[14]+(char)inf.data[15]+(char)inf.data[16];
        }
    } else {
        datetime = datetime +(char)inf.data[0]+(char)inf.data[1] +(char)inf.data[2]+(char)inf.data[3]+"-"+(char)inf.data[4]+(char)inf.data[5]+"-"+(char)inf.data[6]+(char)inf.data[7];
        datetime = datetime + " "+(char)inf.data[8]+(char)inf.data[9]+":"+(char)inf.data[10]+(char)inf.data[11]+":"+(char)inf.data[12]+(char)inf.data[13]+(char)inf.data[14]+(char)inf.data[15]+(char)inf.data[16]+(char)inf.data[17];
        datetime = datetime + (char)inf.data[18];
        if(inf.data[19] != '\0'){
            datetime = datetime + (char)inf.data[19]+(char)inf.data[20]+(char)inf.data[21]+(char)inf.data[22];
        }
    }
    return datetime;
}

void printCertInfo() {
    cout<<"解析如下："<<endl;
    cout << "版本: V" << ((int)certInfo[0].data[0]) + 1 << endl;
    cout << "序列号: ";
    for (int i = 0; i < certInfo[1].length; ++i) {
        printf("%.2x", (int)(unsigned char)certInfo[1].data[i]);
    }
    cout << endl << "签名算法: "<< string(((char*)(certInfo[2].data))) << endl;
    cout << "发行方: [" <<string(((char*)(certInfo[3].data))) <<"] " << certInfo[4].data << endl;
    cout << "生效时间: " << formatDate(certInfo[5]) << endl;
    cout << "失效时间: " << formatDate(certInfo[6]) << endl;
    cout << "主体标识信息: [" << string((char*)(certInfo[7].data))
            << "] " << certInfo[8].data << endl;
    cout << "公钥加密算法: " << string((char*)(certInfo[9].data)) <<endl;
    cout << "公钥: ";
    for (int i = 1; i < certInfo[10].length; ++i) {
        printf("%.2x ", certInfo[10].data[i]);
    }
    cout << endl << "解析结束" << endl;
}

int main() {
    ifstream file("liuyh73.crt", ios::in|ios::binary);
    getCertificateLength(file);
    getTBSCertificateLength(file);
    unsigned char* bytes = new unsigned char[2];
    while(!file.eof()){
        file.read((char*)bytes, 2);
        getInfo(file, bytes[0], getLength(file, bytes[1]));
    }
    file.close();
    printCertInfo();
    for(auto& inf : certInfo) {
        if (inf.ismallc) {
            delete[] inf.data;
        }
    }
    return 0;
}