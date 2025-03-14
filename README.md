curl -X POST "http://127.0.0.1:5001/api/v0/id"

sudo docker-compose up -d --build



docker exec -it cluster1 ipfs-cluster-ctl status QmNVtJPKjwJ9B7GMPCsM21hMHkwTxXYKN55Q4wRwa5L1GC

docker exec -it ipfs0 ipfs add /testfile.txt

docker exec -it ipfs0 ipfs dht findprovs QmNVtJPKjwJ9B7GMPCsM21hMHkwTxXYKN55Q4wRwa5L1GC

docker cp testfile.txt ipfs0:/testfile.tx

docker exec -it cluster0 ipfs-cluster-ctl pin add QmX6SgW3hV3DpFbpGJsX9XMnF8m2JH2RmThj6mfocQKrWP



Add file to IPFS	docker exec -it ipfs0 ipfs add testfile.txt
Pin to Cluster	docker exec -it cluster0 ipfs-cluster-ctl pin add <CID>
Check Cluster Status	docker exec -it cluster0 ipfs-cluster-ctl status <CID>
Find file in DHT	docker exec -it ipfs0 ipfs dht findprovs <CID>
Fetch from another node	docker exec -it ipfs1 ipfs cat <CID>
