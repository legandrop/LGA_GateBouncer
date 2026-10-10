#include "OriginalBootstrapProtocol.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/magic.h>
#include <net/if.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <memory>
#include <sstream>
namespace gb::original {
namespace {
using Clock=std::chrono::steady_clock;
int Pidfd(pid_t p) {return static_cast<int>(syscall(SYS_pidfd_open,p,0));}
bool Alive(int fd) {pollfd p{fd,POLLIN,0};return fd>=0&&poll(&p,1,0)==0;}
struct Fd {
    int value=-1;Fd()=default;explicit Fd(int v):value(v){};
    Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
    Fd(Fd&& v) noexcept:value(v.value){v.value=-1;}
    Fd& operator=(Fd&& v) noexcept {if(value>=0)close(value);value=v.value;v.value=-1;return *this;}
    ~Fd(){if(value>=0)close(value);}
};
bool Same(const struct stat& a,const struct stat& b,bool leaf) {
    return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&a.st_mode==b.st_mode&&
        (!leaf||(a.st_size==b.st_size&&a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec));
}
struct Node {Fd fd;struct stat identity{};std::string name;};
class Leaf {
public:
    bool Open(const std::string& path,int flags,uid_t account=0,bool device=false) {
        if(path.empty()||path[0]!='/'||path.size()>PATH_MAX||path.find("..")!=std::string::npos)return false;
        Node root;root.fd=Fd(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        if(root.fd.value<0||fstat(root.fd.value,&root.identity)||root.identity.st_uid!=0)return false;
        nodes_.push_back(std::move(root));std::size_t start=1;
        while(start<path.size()) {
            const auto end=path.find('/',start);const bool last=end==std::string::npos;
            const std::string name=path.substr(start,last?std::string::npos:end-start);
            if(name.empty()||name=="."||name.find('\0')!=std::string::npos)return false;
            Node n;n.name=name;
            n.fd=Fd(openat(nodes_.back().fd.value,name.c_str(),last?(flags|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC):(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)));
            if(n.fd.value<0||fstat(n.fd.value,&n.identity)||
                (n.identity.st_uid!=0&&n.identity.st_uid!=account)||
                (!last&&(!S_ISDIR(n.identity.st_mode)||(n.identity.st_mode&0022)))||
                (last&&!(device?S_ISCHR(n.identity.st_mode):S_ISREG(n.identity.st_mode))))return false;
            nodes_.push_back(std::move(n));if(last)break;start=end+1;
        }
        return nodes_.size()>1&&Current();
    }
    bool Current() const {
        struct stat s{};if(nodes_.empty()||fstat(nodes_[0].fd.value,&s)||!Same(nodes_[0].identity,s,false))return false;
        for(std::size_t i=1;i<nodes_.size();++i) {
            if(fstatat(nodes_[i-1].fd.value,nodes_[i].name.c_str(),&s,AT_SYMLINK_NOFOLLOW)||
                !Same(nodes_[i].identity,s,i+1==nodes_.size())||fstat(nodes_[i].fd.value,&s)||
                !Same(nodes_[i].identity,s,i+1==nodes_.size()))return false;
        }return true;
    }
    bool Read(std::string& result,std::size_t cap) const {
        if(!Current())return false;result.clear();std::array<char,4096>b{};off_t offset=0;
        while(result.size()<=cap) {
            const auto n=pread(FdValue(),b.data(),std::min(b.size(),cap-result.size()+1),offset);
            if(n<0)return false;if(!n)return result.size()<=cap&&Current();
            result.append(b.data(),static_cast<std::size_t>(n));offset+=n;
        }return false;
    }
    int FdValue()const{return nodes_.empty()?-1:nodes_.back().fd.value;}
    int Parent()const{return nodes_.size()<2?-1:nodes_[nodes_.size()-2].fd.value;}
    int ParentParent()const{return nodes_.size()<3?-1:nodes_[nodes_.size()-3].fd.value;}
    bool RetainWriter(int writer) {
        struct stat w{};if(!Current()||fstat(writer,&w)||!Same(nodes_.back().identity,w,true))return false;
        const int duplicate=fcntl(writer,F_DUPFD_CLOEXEC,3);if(duplicate<0)return false;
        nodes_.back().fd=Fd(duplicate);return Current();
    }
    const struct stat& Identity()const{return nodes_.back().identity;}
private:std::vector<Node> nodes_;
};
bool Number(const std::string& s,std::uint64_t& value) {
    if(s.empty()||s.size()>20)return false;value=0;
    for(char c:s){if(c<'0'||c>'9'||value>(UINT64_MAX-static_cast<unsigned>(c-'0'))/10)return false;value=value*10+static_cast<unsigned>(c-'0');}return true;
}
struct Account {uid_t uid=0;gid_t gid=0;std::string home;};
bool AccountRead(const std::string& data,Account& a,bool& present) {
    std::istringstream rows(data);std::string row;present=false;
    while(std::getline(rows,row)) {
        constexpr char prefix[]="gatebouncerlab:";
        if(row.compare(0,sizeof(prefix)-1,prefix))continue;if(present)return false;present=true;
        std::vector<std::string> fields;std::size_t p=0;
        for(;;){const auto e=row.find(':',p);fields.push_back(row.substr(p,e==std::string::npos?e:e-p));if(e==std::string::npos)break;p=e+1;}
        std::uint64_t uid=0,gid=0;if(fields.size()!=7||fields[1]!="x"||!Number(fields[2],uid)||!Number(fields[3],gid)||
            uid==0||gid==0||uid>UINT32_MAX||gid>UINT32_MAX||fields[5]!="/home/gatebouncerlab"||fields[6]!="/bin/sh")return false;
        a={static_cast<uid_t>(uid),static_cast<gid_t>(gid),fields[5]};
    }return true;
}
bool ChildUseradd() {
    Leaf executable;if(!executable.Open("/usr/sbin/useradd",O_RDONLY)||!(executable.Identity().st_mode&S_IXUSR))return false;
    const pid_t child=fork();if(child<0)return false;
    if(!child) {
        const char* args[]={"useradd","--create-home","--user-group","--shell","/bin/sh","gatebouncerlab",nullptr};
        const char* env[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C",nullptr};
        fexecve(executable.FdValue(),const_cast<char*const*>(args),const_cast<char*const*>(env));_exit(127);
    }
    Fd pid(Pidfd(child));const auto end=Clock::now()+std::chrono::seconds(10);int status=0;
    while(Clock::now()<end) {
        const auto done=waitpid(child,&status,WNOHANG);
        if(done==child)return pid.value>=0&&WIFEXITED(status)&&WEXITSTATUS(status)==0&&executable.Current()&&Clock::now()<end;
        if(done<0)break;pollfd p{pid.value,POLLIN,0};if(pid.value<0||poll(&p,1,25)<0)break;
    }
    // Sólo este PID producido por fork y conservado; nunca un PID suministrado.
    if(pid.value>=0&&Alive(pid.value))syscall(SYS_pidfd_send_signal,pid.value,SIGKILL,nullptr,0);
    while(waitpid(child,&status,0)<0&&errno==EINTR){}return false;
}
bool OwnKeyWrite(const Account& a,const std::string& key,std::unique_ptr<Leaf>& reader) {
    Fd home(open(a.home.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));struct stat h{};
    if(home.value<0||fstat(home.value,&h)||h.st_uid!=a.uid||h.st_gid!=a.gid||mkdirat(home.value,".ssh",0700))return false;
    Fd dir(openat(home.value,".ssh",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if(dir.value<0||fchown(dir.value,a.uid,a.gid)||fchmod(dir.value,0700))return false;
    Fd writer(openat(dir.value,"authorized_keys",O_CREAT|O_EXCL|O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0600));
    if(writer.value<0||fchown(writer.value,a.uid,a.gid)||fchmod(writer.value,0600))return false;
    std::size_t p=0;while(p<key.size()){const auto n=write(writer.value,key.data()+p,key.size()-p);if(n<=0)return false;p+=static_cast<std::size_t>(n);}
    if(fsync(writer.value)||fsync(dir.value))return false;
    auto next=std::make_unique<Leaf>();if(!next->Open(a.home+"/.ssh/authorized_keys",O_RDONLY,a.uid))return false;
    struct stat w{};std::string bytes;
    if(fstat(writer.value,&w)||w.st_dev!=next->Identity().st_dev||w.st_ino!=next->Identity().st_ino||!next->RetainWriter(writer.value)||!next->Read(bytes,4096)||bytes!=key)return false;
    reader=std::move(next);return true;
}
class Watcher {
public:
    bool Start() {fd_=Fd(inotify_init1(IN_NONBLOCK|IN_CLOEXEC));return fd_.value>=0;}
    bool Add(const Leaf& leaf,const std::string& name,bool parentParent=false) {
        const std::string fdpath="/proc/self/fd/"+std::to_string(parentParent?leaf.ParentParent():leaf.Parent());
        const int wd=inotify_add_watch(fd_.value,fdpath.c_str(),IN_ATTRIB|IN_MODIFY|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_MOVE_SELF|IN_DELETE_SELF|IN_ONLYDIR);
        if(wd<0||!leaf.Current())return false;watches_.push_back({wd,name});return true;
    }
    bool Drain() {
        std::array<char,8192>b{};for(unsigned batch=0;batch<32;++batch) {
            const auto n=read(fd_.value,b.data(),b.size());if(n<0)return errno==EAGAIN;if(!n)return false;
            std::size_t p=0;while(p<static_cast<std::size_t>(n)) {
                if(static_cast<std::size_t>(n)-p<sizeof(inotify_event))return false;
                inotify_event e{};std::memcpy(&e,b.data()+p,sizeof(e));
                if(e.len>static_cast<std::size_t>(n)-p-sizeof(e)||e.mask&(IN_Q_OVERFLOW|IN_IGNORED|IN_MOVE_SELF|IN_DELETE_SELF|IN_UNMOUNT))return false;
                if(e.len) {
                    const auto* name=b.data()+p+sizeof(e);const auto* zero=static_cast<const char*>(std::memchr(name,0,e.len));if(!zero)return false;
                    for(const auto& w:watches_)if(w.first==e.wd&&w.second==std::string(name,zero))return false;
                }p+=sizeof(e)+e.len;
            }
        }return false;
    }
private:Fd fd_;std::vector<std::pair<int,std::string>>watches_;
};
class Network {
public:
    bool Start(unsigned selected,const std::string&mac) {
        selected_=selected;if(mac.size()!=17)return false;
        auto nibble=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};
        for(unsigned i=0;i<6;++i){const int a=nibble(mac[i*3]),b=nibble(mac[i*3+1]);if(a<0||b<0||(i<5&&mac[i*3+2]!=':'))return false;mac_[i]=static_cast<unsigned char>((a<<4)|b);}
        fd_=Fd(socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_ROUTE));
        sockaddr_nl a{};a.nl_family=AF_NETLINK;a.nl_groups=RTMGRP_LINK|RTMGRP_IPV4_IFADDR|RTMGRP_IPV6_IFADDR;
        socklen_t size=sizeof(a);
        if(fd_.value<0||bind(fd_.value,reinterpret_cast<sockaddr*>(&a),sizeof(a))||getsockname(fd_.value,reinterpret_cast<sockaddr*>(&a),&size)||size!=sizeof(a)||!a.nl_pid)return false;
        port_=a.nl_pid;return Dump(RTM_GETLINK,1)&&selectedSeen_&&Dump(RTM_GETADDR,2)&&Drain();
    }
    bool Drain() {
        alignas(nlmsghdr)std::array<char,32768>b{};for(unsigned i=0;i<32;++i) {
            sockaddr_nl sender{};socklen_t n=sizeof(sender);const auto count=recvfrom(fd_.value,b.data(),b.size(),MSG_DONTWAIT|MSG_TRUNC,reinterpret_cast<sockaddr*>(&sender),&n);
            if(count<0)return errno==EAGAIN;if(!count||count>static_cast<ssize_t>(b.size())||n!=sizeof(sender)||sender.nl_pid)return false;
            int left=static_cast<int>(count);for(auto* h=reinterpret_cast<nlmsghdr*>(b.data());NLMSG_OK(h,left);h=NLMSG_NEXT(h,left)) {
                if(h->nlmsg_seq||h->nlmsg_pid||h->nlmsg_type==NLMSG_OVERRUN||h->nlmsg_type==NLMSG_ERROR)return false;
                if((h->nlmsg_type==RTM_NEWLINK||h->nlmsg_type==RTM_DELLINK)&&h->nlmsg_len>=NLMSG_LENGTH(sizeof(ifinfomsg))) {
                    ifinfomsg info{};std::memcpy(&info,NLMSG_DATA(h),sizeof(info));if(static_cast<unsigned>(info.ifi_index)==selected_)return false;
                }
                if((h->nlmsg_type==RTM_NEWADDR||h->nlmsg_type==RTM_DELADDR)&&h->nlmsg_len>=NLMSG_LENGTH(sizeof(ifaddrmsg))) {
                    ifaddrmsg info{};std::memcpy(&info,NLMSG_DATA(h),sizeof(info));if(info.ifa_index==selected_)return false;
                }
            }if(left)return false;
        }return false;
    }
private:
    bool Dump(unsigned type,unsigned sequence) {
        struct Request {nlmsghdr h;rtgenmsg family;} request{};request.h.nlmsg_len=NLMSG_LENGTH(sizeof(rtgenmsg));request.h.nlmsg_type=static_cast<unsigned short>(type);
        request.h.nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;request.h.nlmsg_seq=sequence;request.h.nlmsg_pid=port_;request.family.rtgen_family=AF_UNSPEC;
        sockaddr_nl kernel{};kernel.nl_family=AF_NETLINK;const auto end=Clock::now()+std::chrono::milliseconds(500);
        if(sendto(fd_.value,&request,request.h.nlmsg_len,0,reinterpret_cast<sockaddr*>(&kernel),sizeof(kernel))!=static_cast<ssize_t>(request.h.nlmsg_len))return false;
        while(Clock::now()<end) {
            pollfd p{fd_.value,POLLIN,0};if(poll(&p,1,25)<0||Clock::now()>=end)return false;if(!p.revents)continue;
            alignas(nlmsghdr)std::array<char,32768>b{};sockaddr_nl sender{};socklen_t size=sizeof(sender);
            const auto count=recvfrom(fd_.value,b.data(),b.size(),MSG_DONTWAIT|MSG_TRUNC,reinterpret_cast<sockaddr*>(&sender),&size);
            if(Clock::now()>=end||count<=0||count>static_cast<ssize_t>(b.size())||size!=sizeof(sender)||sender.nl_pid)return false;
            int left=static_cast<int>(count);for(auto* h=reinterpret_cast<nlmsghdr*>(b.data());NLMSG_OK(h,left);h=NLMSG_NEXT(h,left)) {
                if(Clock::now()>=end||h->nlmsg_seq!=sequence||h->nlmsg_pid!=port_||h->nlmsg_flags&NLM_F_DUMP_INTR||h->nlmsg_type==NLMSG_ERROR||h->nlmsg_type==NLMSG_OVERRUN)return false;
                if(h->nlmsg_type==NLMSG_DONE){int status=0;if(h->nlmsg_len<NLMSG_LENGTH(sizeof(status)))return false;std::memcpy(&status,NLMSG_DATA(h),sizeof(status));return !status&&left==static_cast<int>(NLMSG_ALIGN(h->nlmsg_len))&&Clock::now()<end;}
                if(type==RTM_GETLINK) {
                    if(h->nlmsg_type!=RTM_NEWLINK||h->nlmsg_len<NLMSG_LENGTH(sizeof(ifinfomsg)))return false;
                    ifinfomsg info{};std::memcpy(&info,NLMSG_DATA(h),sizeof(info));if(static_cast<unsigned>(info.ifi_index)!=selected_)continue;if(selectedSeen_)return false;
                    bool address=false,name=false;int remaining=static_cast<int>(h->nlmsg_len-NLMSG_LENGTH(sizeof(info)));
                    for(auto*attribute=IFLA_RTA(reinterpret_cast<ifinfomsg*>(NLMSG_DATA(h)));RTA_OK(attribute,remaining);attribute=RTA_NEXT(attribute,remaining)) {
                        if(attribute->rta_type==IFLA_ADDRESS){if(address||RTA_PAYLOAD(attribute)!=mac_.size()||std::memcmp(RTA_DATA(attribute),mac_.data(),mac_.size()))return false;address=true;}
                        if(attribute->rta_type==IFLA_IFNAME){constexpr char ownName[]="gbeth0";if(name||RTA_PAYLOAD(attribute)!=sizeof(ownName)||std::memcmp(RTA_DATA(attribute),ownName,sizeof(ownName)))return false;name=true;}
                    }if(remaining||!address||!name)return false;selectedSeen_=true;
                }else {
                    if(h->nlmsg_type!=RTM_NEWADDR||h->nlmsg_len<NLMSG_LENGTH(sizeof(ifaddrmsg)))return false;
                    ifaddrmsg info{};std::memcpy(&info,NLMSG_DATA(h),sizeof(info));if(info.ifa_index==selected_)return false;
                }
            }if(left)return false;
        }return false;
    }
    Fd fd_;unsigned port_=0,selected_=0;std::array<unsigned char,6>mac_{};bool selectedSeen_=false;
};
std::string Real(const std::string& p) {std::array<char,PATH_MAX>b{};return realpath(p.c_str(),b.data())?std::string(b.data()):std::string();}
bool ReadTrim(Leaf& f,const std::string& p,std::string& s,std::size_t cap) {
    if(!f.Open(p,O_RDONLY)||!f.Read(s,cap)||s.empty()||s.back()!='\n')return false;s.pop_back();return s.find('\n')==std::string::npos;
}
class Guest {
public:
    bool Prepare() {
        if(getuid()!=0||geteuid()!=0)return false;self_=Fd(Pidfd(getpid()));proc_=Fd(open("/proc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        struct statfs fs{};if(self_.value<0||proc_.value<0||fstatfs(proc_.value,&fs)||fs.f_type!=PROC_SUPER_MAGIC)return false;
        std::array<char,32>pid{};const auto n=readlinkat(proc_.value,"self",pid.data(),pid.size());
        if(n<=0||std::string(pid.data(),static_cast<std::size_t>(n))!=std::to_string(getpid()))return false;
        const std::string own=std::to_string(getpid());procPid_=Fd(openat(proc_.value,own.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(procPid_.value<0||!StatStart(start_)||!ReadTrim(boot_,"/proc/sys/kernel/random/boot_id",bootId_,64)||bootId_.size()!=36)return false;
        std::array<char,PATH_MAX>image{};const auto imageSize=readlinkat(procPid_.value,"exe",image.data(),image.size());
        if(imageSize<=0||imageSize==static_cast<ssize_t>(image.size())||std::string(image.data(),static_cast<std::size_t>(imageSize))!="/usr/local/libexec/gatebouncer-linux-original"||!code_.Open("/usr/local/libexec/gatebouncer-linux-original",O_RDONLY))return false;
        Fd imageFd(openat(procPid_.value,"exe",O_RDONLY|O_CLOEXEC));struct stat actualCode{};
        if(imageFd.value<0||fstat(imageFd.value,&actualCode)||!Same(actualCode,code_.Identity(),true))return false;
        // Magic symlink netns: excepción propia separada del recorrido de archivos.
        ns_=Fd(openat(procPid_.value,"ns/net",O_RDONLY|O_CLOEXEC));if(ns_.value<0||fstat(ns_.value,&nsIdentity_))return false;
        const auto r=readlinkat(procPid_.value,"ns/net",nsLink_.data(),nsLink_.size());if(r<=0)return false;nsLength_=static_cast<std::size_t>(r);
        std::string seed;if(!control_.Open("/var/lib/gatebouncer/owner-public",O_RDONLY)||!control_.Read(seed,MaximumLine)||!Decode(seed,controlFrame_)||controlFrame_.op!=Op::Hello||!controlFrame_.request||!controlFrame_.generation)return false;
        std::size_t p=0;if(!GetText(controlFrame_.body,p,uuid_,36)||!GetText(controlFrame_.body,p,mac_,17)||!GetText(controlFrame_.body,p,clientLine_,2048)||p!=controlFrame_.body.size())return false;
        Bytes publicClient;if(!PublicLine(clientLine_,"ecdsa-sha2-nistp256",publicClient))return false;
        std::string observed;if(!ReadTrim(dmi_,Real("/sys/class/dmi/id/product_uuid"),observed,64))return false;
        for(auto&c:observed)if(c>='A'&&c<='F')c=static_cast<char>(c-'A'+'a');if(observed!=uuid_)return false;
        DIR* raw=opendir("/sys/class/net");if(!raw)return false;unsigned matches=0;std::string netpath;
        while(auto* e=readdir(raw)) {
            if(e->d_name[0]=='.')continue;auto candidate=std::make_unique<Leaf>();std::string address;
            const std::string path=Real(std::string("/sys/class/net/")+e->d_name);
            if(path.empty()||!ReadTrim(*candidate,path+"/address",address,64))continue;
            if(address==mac_){++matches;macReader_=std::move(candidate);netpath=path;}
        }closedir(raw);if(matches!=1)return false;
        if(!ReadTrim(ifindex_,netpath+"/ifindex",observed,32))return false;std::uint64_t index=0;
        std::string configured;if(!configuration_.Open("/etc/netplan/50-cloud-init.yaml",O_RDONLY)||!configuration_.Read(configured,16384)||configured.find(mac_)==std::string::npos||configured.find("dhcp4: false")==std::string::npos||configured.find("dhcp6: false")==std::string::npos||configured.find("link-local: []")==std::string::npos)return false;
        if(!Number(observed,index)||!index||index>UINT32_MAX||!network_.Start(static_cast<unsigned>(index),mac_))return false;
        Leaf passwd;std::string accounts;Account before;bool exists=false;
        if(!passwd.Open("/etc/passwd",O_RDONLY)||!passwd.Read(accounts,1048576)||!AccountRead(accounts,before,exists)||exists||!ChildUseradd())return false;
        if(!passwd_.Open("/etc/passwd",O_RDONLY)||!passwd_.Read(accounts,1048576)||!AccountRead(accounts,account_,exists)||!exists)return false;
        expectedKey_="restrict,command=\"/usr/local/libexec/gatebouncer-capture\" "+clientLine_;
        if(!OwnKeyWrite(account_,expectedKey_,authorized_)||!capture_.Open("/usr/local/libexec/gatebouncer-capture",O_RDONLY))return false;
        std::string publicHost;if(!hostkey_.Open("/etc/ssh/ssh_host_ed25519_key.pub",O_RDONLY)||!hostkey_.Read(publicHost,2048))return false;
        const auto first=publicHost.find(' '),second=first==std::string::npos?first:publicHost.find(' ',first+1);
        if(second!=std::string::npos)publicHost=publicHost.substr(0,second)+"\n";
        Bytes host;if(!PublicLine(publicHost,"ssh-ed25519",host))return false;hostLine_=publicHost;
        raw=opendir("/sys/class/virtio-ports");if(!raw)return false;std::string device;matches=0;
        while(auto* e=readdir(raw)) {
            if(e->d_name[0]=='.')continue;auto name=std::make_unique<Leaf>();std::string value;
            const std::string sys=Real(std::string("/sys/class/virtio-ports/")+e->d_name);
            if(sys.empty()||!ReadTrim(*name,sys+"/name",value,128)||value!="gatebouncer.bootstrap")continue;
            ++matches;portName_=std::move(name);device=std::string("/dev/")+e->d_name;
            if(!ReadTrim(portDev_,sys+"/dev",deviceRdev_,64))matches=2;
        }closedir(raw);if(matches!=1||!device_.Open(device,O_RDWR,0,true))return false;
        const auto colon=deviceRdev_.find(':');std::uint64_t major=0,minor=0;
        if(colon==std::string::npos||!Number(deviceRdev_.substr(0,colon),major)||!Number(deviceRdev_.substr(colon+1),minor)||major!=static_cast<std::uint64_t>(::major(device_.Identity().st_rdev))||minor!=static_cast<std::uint64_t>(::minor(device_.Identity().st_rdev)))return false;
        if(!watcher_.Start()||!watcher_.Add(passwd_,"passwd")||!watcher_.Add(*authorized_,"authorized_keys")||!watcher_.Add(hostkey_,"ssh_host_ed25519_key.pub")||!watcher_.Add(*authorized_,".ssh",true)||!watcher_.Add(code_,"gatebouncer-linux-original")||!watcher_.Add(capture_,"gatebouncer-capture")||!watcher_.Add(configuration_,"50-cloud-init.yaml"))return false;
        end_=Clock::now()+std::chrono::seconds(300);return Fresh();
    }
    int Run() {
        Frame frame{Op::Init,0,0,0,{}};if(!Send(frame)||!Receive(frame)||frame.op!=Op::Hello||frame.body.size()!=16||!Fresh())return 2;
        const Bytes nonce=frame.body;Frame ready{Op::Ready,controlFrame_.request,controlFrame_.generation,sendSequence_++,nonce};
        PutText(ready.body,uuid_);PutText(ready.body,mac_);PutText(ready.body,bootId_);Put(ready.body,start_,8);Put(ready.body,account_.uid,4);Put(ready.body,account_.gid,4);PutText(ready.body,hostLine_);PutText(ready.body,clientLine_);
        if(!Send(ready)||!Receive(frame)||frame.op!=Op::Ack||frame.body!=ready.body||!Fresh()||!Send({Op::Acked,ready.request,ready.generation,sendSequence_++,nonce}))return 2;
        bool sshStarted=false;for(;;) {
            if(!Fresh())return 2;pollfd descriptors[2]{{device_.FdValue(),POLLIN,0},{ssh_.value,POLLIN,0}};
            if(poll(descriptors,ssh_.value>=0?2:1,25)<0||!Fresh())return 2;
            if(descriptors[0].revents) {
                if(!Receive(frame)||!Fresh())return 2;
                if(frame.op==Op::Check) {
                    if(frame.body.size()!=16||!Send({Op::Current,frame.request,frame.generation,sendSequence_++,frame.body}))return 2;
                }else if(frame.op==Op::Ssh) {
                    if(frame.body.empty()||frame.body.size()>MaximumChunk)return 2;
                    if(!sshStarted){if(!StartSsh())return 2;sshStarted=true;}
                    if(!Write(ssh_.value,frame.body.data(),frame.body.size())||!Fresh()||!Send({Op::Credit,frame.request,frame.generation,sendSequence_++,{}}))return 2;
                }else if(frame.op==Op::Eof) {
                    if(!sshStarted||!frame.body.empty()||shutdown(ssh_.value,SHUT_WR))return 2;
                }else if(frame.op==Op::Close) {
                    if(!frame.body.empty()||!Fresh()||!Send({Op::Closed,frame.request,frame.generation,sendSequence_++,{}}))return 2;
                    sync();return reboot(RB_POWER_OFF)==0?0:2;
                }else return 2;
            }
            if(ssh_.value>=0&&descriptors[1].revents) {
                std::array<std::uint8_t,MaximumChunk>b{};const auto n=read(ssh_.value,b.data(),b.size());
                if(n<0){if(errno==EAGAIN)continue;return 2;}
                if(!n){if(!Send({Op::Eof,controlFrame_.request,controlFrame_.generation,sendSequence_++,{}}))return 2;ssh_=Fd();}
                else if(!Send({Op::Ssh,controlFrame_.request,controlFrame_.generation,sendSequence_++,Bytes(b.begin(),b.begin()+n)}))return 2;
            }
        }
    }
private:
    bool StatStart(std::uint64_t& start)const {
        Fd stat(openat(procPid_.value,"stat",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));std::array<char,4096>b{};
        const auto n=stat.value<0?-1:read(stat.value,b.data(),b.size());if(n<=0||n==static_cast<ssize_t>(b.size()))return false;
        std::string row(b.data(),static_cast<std::size_t>(n));const auto close=row.rfind(')');if(close==std::string::npos||row.compare(0,std::to_string(getpid()).size()+2,std::to_string(getpid())+" ("))return false;
        std::istringstream fields(row.substr(close+2));std::string value;for(unsigned i=3;i<=22;++i)if(!(fields>>value))return false;return Number(value,start)&&start;
    }
    bool Fresh()const {
        if(Clock::now()>=end_||!Alive(self_.value)||!boot_.Current()||!control_.Current()||!code_.Current()||!configuration_.Current()||!dmi_.Current()||!macReader_->Current()||!ifindex_.Current()||!passwd_.Current()||!authorized_->Current()||!hostkey_.Current()||!capture_.Current()||!portName_->Current()||!portDev_.Current()||!device_.Current())return false;
        std::uint64_t start=0;struct stat ns{};std::array<char,64>link{};const auto size=readlinkat(procPid_.value,"ns/net",link.data(),link.size());
        Fd current(openat(procPid_.value,"ns/net",O_RDONLY|O_CLOEXEC));std::string key;
        return StatStart(start)&&start==start_&&current.value>=0&&!fstat(current.value,&ns)&&ns.st_dev==nsIdentity_.st_dev&&ns.st_ino==nsIdentity_.st_ino&&size==static_cast<ssize_t>(nsLength_)&&std::equal(link.begin(),link.begin()+size,nsLink_.begin())&&authorized_->Read(key,4096)&&key==expectedKey_&&const_cast<Watcher&>(watcher_).Drain()&&const_cast<Network&>(network_).Drain()&&Clock::now()<end_;
    }
    bool Write(int fd,const void* data,std::size_t size) {
        const auto end=std::min(end_,Clock::now()+std::chrono::milliseconds(500));const auto* b=static_cast<const std::uint8_t*>(data);std::size_t done=0;
        while(done<size&&Clock::now()<end&&Fresh()) {
            const auto n=write(fd,b+done,size-done);if(n>0)done+=static_cast<std::size_t>(n);else if(n<0&&(errno==EAGAIN||errno==EINTR)){pollfd p{fd,POLLOUT,0};if(poll(&p,1,25)<0)return false;}else return false;
            if(Clock::now()>=end||!Fresh())return false;
        }return done==size&&Clock::now()<end&&Fresh();
    }
    bool Send(const Frame& frame){std::string line;return Encode(frame,line)&&Write(device_.FdValue(),line.data(),line.size());}
    bool Receive(Frame& frame) {
        const auto end=std::min(end_,Clock::now()+std::chrono::milliseconds(500));std::string line;
        while(Clock::now()<end&&line.size()<MaximumLine&&Fresh()) {
            char byte=0;const auto n=read(device_.FdValue(),&byte,1);
            if(n==1){line+=byte;if(byte=='\n')break;}
            else if(n<0&&(errno==EAGAIN||errno==EINTR)){pollfd p{device_.FdValue(),POLLIN,0};if(poll(&p,1,25)<0)return false;}
            else return false;
        }
        return Clock::now()<end&&Fresh()&&Decode(line,frame)&&frame.request==controlFrame_.request&&frame.generation==controlFrame_.generation&&frame.sequence==receiveSequence_++;
    }
    bool StartSsh() {
        ssh_=Fd(socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));sockaddr_in target{};target.sin_family=AF_INET;target.sin_port=htons(22);target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if(ssh_.value<0)return false;const int result=connect(ssh_.value,reinterpret_cast<sockaddr*>(&target),sizeof(target));
        if(result&&errno!=EINPROGRESS)return false;pollfd p{ssh_.value,POLLOUT,0};if(poll(&p,1,500)<=0||!Fresh())return false;
        int error=0;socklen_t size=sizeof(error);sockaddr_in peer{};socklen_t peerSize=sizeof(peer);
        return !getsockopt(ssh_.value,SOL_SOCKET,SO_ERROR,&error,&size)&&!error&&!getpeername(ssh_.value,reinterpret_cast<sockaddr*>(&peer),&peerSize)&&peer.sin_family==AF_INET&&peer.sin_port==target.sin_port&&peer.sin_addr.s_addr==target.sin_addr.s_addr&&Fresh();
    }
    Fd self_,proc_,procPid_,ns_,ssh_;struct stat nsIdentity_{};std::array<char,64>nsLink_{};std::size_t nsLength_=0;
    Leaf boot_,control_,code_,configuration_,dmi_,ifindex_,passwd_,hostkey_,capture_,portDev_,device_;std::unique_ptr<Leaf>macReader_,authorized_,portName_;
    mutable Watcher watcher_;mutable Network network_;Account account_;Frame controlFrame_;std::string bootId_,uuid_,mac_,clientLine_,hostLine_,expectedKey_,deviceRdev_;
    std::uint64_t start_=0,sendSequence_=1,receiveSequence_=1;Clock::time_point end_=Clock::now()+std::chrono::seconds(300);
};
[[maybe_unused]]int Capture() {
    if(getuid()==0||geteuid()==0||getuid()!=geteuid())return 3;Leaf passwd;std::string data;Account account;bool present=false;
    if(!passwd.Open("/etc/passwd",O_RDONLY)||!passwd.Read(data,1048576)||!AccountRead(data,account,present)||!present||account.uid!=getuid()||account.gid!=getgid())return 3;
    // Rol usuario fijo: no interpreta SSH_ORIGINAL_COMMAND, argv ni stdin.
    constexpr char line[]="Guest capture: own session ready\n";return write(STDOUT_FILENO,line,sizeof(line)-1)==static_cast<ssize_t>(sizeof(line)-1)&&passwd.Current()?0:3;
}
}
int RunLinuxOriginalGuest(int argc) {
    if(argc!=1)return 4;
#ifdef GB_CAPTURE_ONLY
    return Capture();
#else
    auto guest=std::make_unique<Guest>();return guest->Prepare()?guest->Run():2;
#endif
}
}
int main(int argc,char**) {try{return gb::original::RunLinuxOriginalGuest(argc);}catch(...){return 5;}}
