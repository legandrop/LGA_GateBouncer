#include "OwnCloudSeed.hpp"
#include <algorithm>
#include <stdexcept>
namespace gb {
namespace {
using original::Bytes;constexpr std::uint32_t Sector=2048;
void Value(Bytes& b,std::size_t p,std::uint32_t n,unsigned count,bool big) {
    if(p+count>b.size())throw std::runtime_error("SeedBounds");
    for(unsigned i=0;i<count;++i)b[p+i]=static_cast<std::uint8_t>(n>>((big?(count-i-1):i)*8));
}
void Both(Bytes& b,std::size_t p,std::uint32_t n,unsigned count){Value(b,p,n,count,false);Value(b,p+count,n,count,true);}
Bytes Record(std::uint32_t extent,std::uint32_t size,const Bytes& name,bool directory,const std::string& rock={}) {
    Bytes b(33+name.size()+(name.size()%2==0?1:0),0);b[1]=0;
    Both(b,2,extent,4);Both(b,10,size,4);b[18]=126;b[19]=10;b[20]=10;b[25]=directory?2:0;
    Both(b,28,1,2);b[32]=static_cast<std::uint8_t>(name.size());std::copy(name.begin(),name.end(),b.begin()+33);
    if(!rock.empty()){b.insert(b.end(),{'R','R',5,1,8,'N','M',static_cast<std::uint8_t>(5+rock.size()),1,0});b.insert(b.end(),rock.begin(),rock.end());}
    if(b.size()%2)b.push_back(0);if(b.size()>255)throw std::runtime_error("SeedRecordBounds");b[0]=static_cast<std::uint8_t>(b.size());return b;
}
}
original::Bytes OwnCloudSeed::MakeOwn(const std::vector<std::pair<std::string,original::Bytes>>& entries) {
    const std::array<std::string,3> names{"user-data","meta-data","network-config"};
    if(entries.size()!=names.size())throw std::runtime_error("SeedEntryCount");
    std::uint32_t next=21;std::vector<std::uint32_t> extents;
    for(std::size_t i=0;i<entries.size();++i) {
        if(entries[i].first!=names[i]||entries[i].second.empty()||entries[i].second.size()>8*1024*1024)throw std::runtime_error("SeedEntryInvalid");
        extents.push_back(next);next+=static_cast<std::uint32_t>((entries[i].second.size()+Sector-1)/Sector);
    }
    if(static_cast<std::uint64_t>(next)*Sector>16*1024*1024)throw std::runtime_error("SeedTooLarge");
    Bytes image(static_cast<std::size_t>(next)*Sector,0),pvd(Sector,0);
    for(const auto range:{std::pair<std::size_t,std::size_t>{8,72},{190,623}})std::fill(pvd.begin()+static_cast<std::ptrdiff_t>(range.first),pvd.begin()+static_cast<std::ptrdiff_t>(range.first+range.second),' ');
    for(const std::size_t date:{813u,830u,847u,864u})std::fill_n(pvd.begin()+static_cast<std::ptrdiff_t>(date),16,'0');
    pvd[0]=1;std::copy_n("CD001",5,pvd.begin()+1);pvd[6]=1;std::copy_n("CIDATA",6,pvd.begin()+40);
    Both(pvd,80,next,4);Both(pvd,120,1,2);Both(pvd,124,1,2);Both(pvd,128,Sector,2);Both(pvd,132,10,4);
    Value(pvd,140,18,4,false);Value(pvd,144,0,4,false);Value(pvd,148,19,4,true);Value(pvd,152,0,4,true);
    auto root=Record(20,Sector,{0},true);std::copy(root.begin(),root.end(),pvd.begin()+156);pvd[881]=1;
    std::copy(pvd.begin(),pvd.end(),image.begin()+16*Sector);image[17*Sector]=255;std::copy_n("CD001",5,image.begin()+17*Sector+1);image[17*Sector+6]=1;
    for(unsigned table=18;table<=19;++table){const auto p=table*Sector;image[p]=1;Value(image,p+2,20,4,table==19);Value(image,p+6,1,2,table==19);}
    auto dot=Record(20,Sector,{0},true);dot.insert(dot.end(),{'S','P',7,1,0xbe,0xef,0,'E','R',18,1,10,0,0,1,'R','R','I','P','_','1','9','9','1','A'});
    if(dot.size()%2)dot.push_back(0);dot[0]=static_cast<std::uint8_t>(dot.size());
    std::size_t directory=20*Sector;std::copy(dot.begin(),dot.end(),image.begin()+static_cast<std::ptrdiff_t>(directory));directory+=dot.size();
    const auto parent=Record(20,Sector,{1},true);std::copy(parent.begin(),parent.end(),image.begin()+static_cast<std::ptrdiff_t>(directory));directory+=parent.size();
    for(std::size_t i=0;i<entries.size();++i) {
        std::string primary=names[i];for(auto& c:primary){if(c=='-')c='_';else if(c>='a'&&c<='z')c=static_cast<char>(c-'a'+'A');}primary+=".;1";
        const auto record=Record(extents[i],static_cast<std::uint32_t>(entries[i].second.size()),Bytes(primary.begin(),primary.end()),false,names[i]);
        if(directory+record.size()>21*Sector)throw std::runtime_error("SeedDirectoryBounds");
        std::copy(record.begin(),record.end(),image.begin()+static_cast<std::ptrdiff_t>(directory));directory+=record.size();
        std::copy(entries[i].second.begin(),entries[i].second.end(),image.begin()+static_cast<std::ptrdiff_t>(extents[i]*Sector));
    }return image;
}
}
