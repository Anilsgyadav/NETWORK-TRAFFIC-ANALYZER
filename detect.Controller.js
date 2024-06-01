const BanData = require('../models/ban');
const fs = require('fs');
const csvjson = require('csvjson');

exports.check = async(req,res)=>{
    // const data = await BanData.find();
    var tcpPacket = 0, udpPacket = 0, totalNumber = 0;
    try{
        const ban = await BanData.find();
        var data = fs.readFileSync('D:\\university projects\\network-traffic-analyzer\\controllers\\traffic data.csv', { encoding : 'utf8'});
        var options = {
            delimiter : ',', // optional
            quote     : '"' // optional
        };
        const TrafficData = csvjson.toObject(data, options);
        var BanIpList = []
        var suspectedData = []
        ban.forEach((dat)=>{
            BanIpList.push(dat.ip)
        })
        // console.log(BanIpList);
        TrafficData.forEach((Element)=>{    
            if(BanIpList.includes(Element.Destination)){
                suspectedData.push(Element)
            }
        })
        suspectedData.forEach((data)=>{
            // console.log(data);
            if(data.Protocol == "TCP")
            {
                tcpPacket++;
            }
            if(data.Protocol == "UDP")
            {
                udpPacket++;
            }
            totalNumber++;
        })
        // res.status(200).json({
        //     message: "Sucess!",
        //     suspectedData
        // })
        if(suspectedData.length === 0){
            return res.render('showData',{
                message: "No malicious activity detected!",
                suspectedData
            });
        }
        return res.render('showData',{
            message: "Data Fetched Sucessfully!",
            suspectedData,
            tcpPacket,
            udpPacket,
            totalNumber
        });
    }
    catch(error)
    {
        console.log(error);
        // return res.status(500).json({
        //     message: "Server error!"
        // })
        return res.render('showData',{
            message: "Some error Occured!",
            suspectedData:[]
        });
    }
}

exports.livePage = (req,res)=>{
    return res.render('livedata',{
        message:""
    });
}