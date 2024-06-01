const express = require('express');
const app = express();
require('dotenv').config();
const routes = require('./routes/routes');
const dbConnect = require('./config/db');
const cors = require('cors')
const bodyparser = require('body-parser');

const http = require('http').Server(app);
const io = require('socket.io')(http,{
    cors:{
        origin: ["https://admin.socket.io"],
        credentials: true
    }
});

var pcap = require('pcap'),
session = pcap.createSession('eth0', '');
tcp_tracker = new pcap.TCPTracker(),

app.set("view engine", "ejs")
app.use(express.json());
app.use(cors());
// Body-parser middleware
app.use(bodyparser.urlencoded({ extended: false }))
app.use(bodyparser.json())
app.use('/', routes);

dbConnect.connect();

// tcp_tracker.on('session', function (session) {
//     console.log("Start of session between " + session.src_name + " and " + session.dst_name);
//     session.on('end', function (session) {
//         console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
//     });
// });
global.data= "";
io.on('connection',socket =>{
    console.log("user connected");
    console.log(socket.id);
    socket.on("message",()=>{
        console.log("HI");
    //     if(rid === "")
        
    //     else
        setInterval(()=>{
            // socket.to(socket.id).emit("received",data);
            socket.broadcast.emit('received',data);
        },800)
    })
});
session.on('packet', (packet) => {
    packet = pcap.decode.packet(packet)
    try {
        const srcIP = packet.payload.payload.saddr.addr.join(".")
        const dstIP = packet.payload.payload.daddr.addr.join(".")
        const protocol = packet.payload.payload.flags
        const port = packet.payload.payload.payload.dport
        // const data = packet.payload.payload.payload.data
        // console.log(packet);
        if (port == 443)
            // console.log("HTTPS", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "HTTPS",
                srcIP,
                dstIP,
                port
            }
        if (port == 80)
            // console.log("HTTP", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "HTTP",
                srcIP,
                dstIP,
                port
            }
        if (port == 21)
            // console.log("FTP", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "FTP",
                srcIP,
                dstIP,
                port
            }
        if (port == 22)
            // console.log("SSH", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "SSH",
                srcIP,
                dstIP,
                port
            }
        if (port == 3389)
            // console.log("RDP", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "RDP",
                srcIP,
                dstIP,
                port
            }
        if (port == 587)
            // console.log("SMTP", " ", srcIP, " ", dstIP, " ", port, " ");
            data = {
                protocol: "SMTP",
                srcIP,
                dstIP,
                port
            }

        // tcp_tracker.track_packet(packet);
        // console.log(srcIP, " ", dstIP, " ", port, " ");
        // console.log(packet.payload.payload.saddr.addr.join("."));
    }
    catch (error) {

    }
});

// app.listen(process.env.PORT, () => {
//     console.log(`connected to port ${process.env.PORT}`);
// })

http.listen(3000,()=>console.log("server up at 3000"))