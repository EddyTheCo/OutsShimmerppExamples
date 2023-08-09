// include https://eddytheco.github.io/Qed25519/
#include"crypto/qed25519.hpp"
// include https://eddytheco.github.io/Qslip10/
#include"crypto/qslip10.hpp"
// include https://eddytheco.github.io/QAddrBundle/
#include"qaddr_bundle.hpp"

// include https://eddytheco.github.io/QclientMqtt-IOTA/
#include"client/qclientMQTT.hpp"

#include <QCoreApplication>

#include<QTimer>


using namespace qiota::qblocks;
using namespace qiota;
using namespace qcrypto;
using namespace qencoding::qbech32::Iota;

int main(int argc, char** argv)
{
    // Create the needed https://doc.qt.io/qt-6/qcoreapplication.html
    auto a=QCoreApplication(argc, argv);

    // Close the application after 30 secs
    QTimer::singleShot(30000, &a, QCoreApplication::quit);

    // It is mandatory to pass the node address and the seed to the application
    if(argc>1)
    {
        // Create the Shimmer Client to communicate with the REST API of the nodes
        auto iota_client=new Client(&a);

        //Set the node address. Example: https://api.testnet.shimmer.network
        iota_client->set_node_address(QUrl(argv[1]));

        // Set the seed for address generation. Example: ef4593558d0c3ed9e3f7a2de766d33093cd72372c800fa47ab5765c43ca006b5
        auto seed=QByteArray::fromHex(argv[2]);

        // The third argument will be taken as the node JWT for protected routes
        if(argc>2)iota_client->set_jwt(QString(argv[3]));

        // Print the block id after sent and close
        // The iota client send a signal(last_blockid) every time a block was sent and accepted by the node
        QObject::connect(iota_client,&Client::last_blockid,&a,[](const c_array bid )
        {
            qDebug()<<"blockid:"<<bid.toHexString();
        });

        // Create a master Key
        auto MK=Master_key(seed);

        // Set a path to get the keys according to https://github.com/satoshilabs/slips/blob/master/slip-0010.md
        // This path correspond to the 0 address of Shimmer hierarchical deterministic wallet.
        QVector<quint32> path={44,4219,0,0,0};

        // Get the public and private keys resulting from the Master key and the path.
        auto keys=MK.slip10_key_from_path(path);

        // Everything start from asking the node some information
        auto info=iota_client->get_api_core_v2_info();

        // When the info is returned by the node execute this
        QObject::connect(info,&Node_info::finished,&a,[=,&a]( ){

            // Create an object responsible of consuming outputs in the address
            auto addr_bundle=new AddressBundle(qed25519::create_keypair(keys.secret_key()));

            // Get the bech32 address we own(because we have the private and public keys)
            const auto address=addr_bundle->get_address_bech32(info->bech32Hrp);

            // Create and object that holds the Basic outputs returned by the node
            auto node_outputs_=new Node_outputs();

            // When the node returns the Basic outputs execute this
            QObject::connect(node_outputs_,&Node_outputs::finished,iota_client,[=,&a]( ){

                // Prepare all the outputs returned by the node to be consumed(if possible)
                addr_bundle->consume_outputs(node_outputs_->outs_);

                // Check that the outputs have make available some amount of base coins
                if(addr_bundle->amount)
                {

                    // Get the address you control
                    const auto eddAddr=addr_bundle->get_address();

                    // Create a Sender feature by using the address that will be unlocked https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#sender-feature
                    const auto sendFea=Feature::Sender(eddAddr);

                    // Create a Tag Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#tag-feature
                    const auto tagFea=Feature::Tag("from IOTA-QT");

                    // Create a Metadata Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                    const auto metFea=Feature::Metadata("WENN? SOON");

                    // Create a Metadata Feature to add to immutable features of the Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                    const auto imMetFea=Feature::Metadata("WENN? SOON BUT IMMUTABLE");

                    // Create an Issuer Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#issuer-feature
                    const auto issuFea=Feature::Issuer(eddAddr);

                    // Create a container for unlocks https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#unlock-conditions
                    pvector<const Unlock_Condition> unlock_conditions;

                    // Get the address from a bech32 string https://wiki.iota.org/shimmer/tips/tips/TIP-0011/#bech32-for-human-readable-encoding
                    auto RecAddress= decode("rms1qp9rtwlc00ksp0mvet8ugwvqu03ygzr8s3x77w3df9qw9srm3hwk2tg8lds").second;

                    // Create an Address Unlock Condition	https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#address-unlock-condition
                    // In a basic NFT Output an Address Unlock Condition must be present https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#additional-transaction-syntactic-validation-rules-3
                    const auto addUnlCon=Unlock_Condition::Address(Address::from_array(RecAddress));
                    unlock_conditions.push_back(addUnlCon);

                    // Calculate the Minimum Storage Deposit of an Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#additional-syntactic-transaction-validation-rule
                    const auto minDeposit=Client::get_deposit(Output::Basic(0,{addUnlCon}),info);

                    // Create a Storage Deposit Return Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#storage-deposit-return-unlock-condition
                    // The minimum possible amount to be returned is set https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#additional-syntactic-transaction-validation-rule
                    const auto stoUnlCon=Unlock_Condition::Storage_Deposit_Return(eddAddr,minDeposit);
                    unlock_conditions.push_back(stoUnlCon);

                    // Create a Timelock Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#timelock-unlock-condition
                    // Will be locked 1 day from now
                    const auto timeUnlCon=Unlock_Condition::Timelock(QDateTime::currentDateTime().addDays(1).toSecsSinceEpoch());
                    unlock_conditions.push_back(timeUnlCon);

                    // Create a Expiration Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#expiration-unlock-condition
                    // From 2 days from now the output can be cosumed by unlocking the eddAddr address
                    const auto expUnloCon=Unlock_Condition::Expiration(QDateTime::currentDateTime().addDays(2).toSecsSinceEpoch(),eddAddr);

                    // Create a NFT Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#nft-output
                    auto NFTOut= Output::NFT(addr_bundle->amount,unlock_conditions,addr_bundle->get_tokens(),
                                             {imMetFea,issuFea},
                                             {sendFea,tagFea,metFea});

                    // Calculate the Storage Deposit of the Basic output we want to create. https://wiki.iota.org/shimmer/tips/tips/TIP-0019/
                    const auto storDepo=Client::get_deposit(NFTOut,info);

                    // We need to have enough funds from the inputs to cover the Storage Deposit
                    if(addr_bundle->amount>=storDepo)
                    {
                        // Create container for the outputs of the transaction
                        // Add the NFT Output to the container
                        pvector<const Output> the_outputs_{NFTOut};

                        // Add the needed Storage Deposit return outputs from the consumed outputs
                        the_outputs_.insert(the_outputs_.end(), addr_bundle->ret_outputs.begin(), addr_bundle->ret_outputs.end());


                        // Create the Inputs Commitment https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#inputs-commitment
                        auto Inputs_Commitment=Block::get_inputs_Commitment(addr_bundle->Inputs_hash);

                        // Create the Transaction Essence https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#transaction-essence
                        auto essence=Essence::Transaction(info->network_id_,addr_bundle->inputs,Inputs_Commitment,the_outputs_);

                        // Create the Unlocks https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#unlocks
                        addr_bundle->create_unlocks(essence->get_hash());

                        // Create a Transaction Payload https://wiki.iota.org/shimmer/tips/tips/TIP-0020/
                        auto trpay=Payload::Transaction(essence,addr_bundle->unlocks);

                        // Create the Shimmer Client to communicate with the EVENT API of the nodes
                        auto mqtt_client=new ClientMqtt(&a);
                        mqtt_client->set_node_address(QUrl(argv[1]));

                        // Create a block https://wiki.iota.org/shimmer/tips/tips/TIP-0024/
                        auto block_=Block(trpay);

                        // Send the block after the client connects to the event API
                        QObject::connect(mqtt_client,&QMqttClient::stateChanged,&a,[=,&a]
                        {
                            if(mqtt_client->state()==QMqttClient::Connected)
                            {
                                // Subscribe to `transactions/{transactionId}/included-block`
                                // When the block is confirmed execute this
                                auto response=mqtt_client->get_subscription("transactions/"+trpay->get_id().toHexString() +"/included-block");
                                QObject::connect(response,&ResponseMqtt::returned,&a,[&a](auto var){
                                    qDebug()<<"The block is confirmed by a milestone";
                                    a.quit();
                                });

                                // Send the block to the node
                                iota_client->send_block(block_);
                            }
                        });

                    }
                    else
                    {
                        qDebug()<<"Not enough funds in " + address;
                        qDebug()<<"You need at least "<<(storDepo-addr_bundle->amount)<<info->subunit ;
                        a.quit();
                    }

                }
                else
                {
                    qDebug()<<"Try transfering some coins to "+ address;
                    a.quit();
                }
            });

            // Get the Basic outputs according to '/api/indexer/v1/outputs/basic'  https://editor.swagger.io/?url=https://raw.githubusercontent.com/iotaledger/tips/main/tips/TIP-0026/indexer-rest-api.yaml
            iota_client->get_outputs<Output::Basic_typ>(node_outputs_,"address="+address+"&hasNativeTokens=false");
        });

        return a.exec();
    }
    else
    {
        qDebug()<<"It is mandatory to pass the node address and the seed to the application";
    }


}
