import rsa

# D_prv index = 1
D_PRV = rsa.PrivateKey(
    n=0x81b64773fc0750bc6783c7df0a64391d61392757ecf598fe6fc9097dfd1c061f8f98ced8ec329dae4af493bbc771db160c69591096e3c11bc4888b260757b0ad,
    e=0x10001,
    d=0x2fc8c5b3dda198457fe0d52dbe77436f2654d6c09663b793ebfc6489cc47412b2534ea7bd9a3a4de26262729b6b31f7354f42ee12469f0353f0b1277a0c44921,
    p=7117099836174645304603375181824961614573320434191526346604683598153419047949903029,
    q=954541919070503072483831975555519348874947358467370966423334666422882073
)

# D_pub index = 4
D_PUB = rsa.PublicKey(
    n=0x81b64773fc0750bc6783c7df0a64391d61392757ecf598fe6fc9097dfd1c061f8f98ced8ec329dae4af493bbc771db160c69591096e3c11bc4888b260757b0ad,
    e=0x10001
)

# GU_prv index = 2 (in PL)
GU_PRV = rsa.PrivateKey(
    n=0xb9f6ed5da91e1c7d672a29f0616e4685f4d9d3a27e7e1308a40e33c6a6ec12164a4593816ea09656baa73f4709b24ad325b8e1311f4510706d3b414df4356869,
    e=0x10001,
    d=0x829070b54ab09e7619418c327e658b542fc5e405f96390ff871785989ac7214a8b4fcf59369998a64c43c31e30089ca5de7a20f229bb1e30704c09bcf71eea81,
    p=6116171503527888921767712548515523595805446826105819185237332556112038372842585969,
    q=1592459313716742514031474057899547594934963580600144037289555686379596921
)

# GU_pub index = 5
GU_PUB = rsa.PublicKey(
    n=0xb9f6ed5da91e1c7d672a29f0616e4685f4d9d3a27e7e1308a40e33c6a6ec12164a4593816ea09656baa73f4709b24ad325b8e1311f4510706d3b414df4356869,
    e=0x10001
)

# GC_prv index = 3
GC_PRV = rsa.PrivateKey(
    n=0x9a38104602e2f0b2383453f98c0c024f6e8531f58a2ebe54708b71a324ee4277a12ed53cf03da9e0ebec49fcc5e3db73316db7fba370bcaefc2d74eb24cee03b,
    e=0x10001,
    d=0x1446f4d4cfc2591585d0538e473cb8fd0ab216ac8b3bb428d417719c9ad961dcc23d96026b4c30231333245b4fa90d9440298483ef14e1195ee5c27cb3627a51,
    p=6119768061495829928496946178543529867704743670694006506535972164859752748697177987,
    q=1319838309076232505360863740284409859566323974692954378591484235434841833
)

# GC_pub index = 6
GC_PUB = rsa.PublicKey(
    n=0x9a38104602e2f0b2383453f98c0c024f6e8531f58a2ebe54708b71a324ee4277a12ed53cf03da9e0ebec49fcc5e3db73316db7fba370bcaefc2d74eb24cee03b,
    e=0x10001
)
