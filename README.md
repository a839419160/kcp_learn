# kcp_learn
kcp sample demo

接收方:
从网络接口直接获取到数据->【kcp】ikcp_input(kcp解码放入接收队列)->应用层调用ikcp_recv就可以获取到对端发送的数据

发送方：
应用层调用ikcp_send将数据放入kcp发送队列

kcp:
应用层通过ikcp_update调用ikcp_flush
