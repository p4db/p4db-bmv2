namespace cpp cpservice

service ControlPlaneService {

   bool ping(),

   oneway void packet_in(1: i32 port, 2: binary data, 3: i32 data_len),

   oneway void hello(1: i32 thriftServerPort, 2: i32 deviceId, 3: i32 processInstanceId, 4: string configMd5)

}