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

            // Create and object that holds Basic outputs returned by the node
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

                    // Create a Metadata Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                    const auto metFea=Feature::Metadata("WENN? SOON");

                    // Create a Metadata Feature to add to immutable features of the Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                    const auto imMetFea=Feature::Metadata("WENN? SOON BUT IMMUTABLE");

                    // Create an Issuer Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#issuer-feature
                    const auto issuFea=Feature::Issuer(eddAddr);

                    // Create a container for unlocks https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#unlock-conditions
                    pvector<const Unlock_Condition> unlock_conditions;

                    // Create a State Controller Address Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#state-controller-address-unlock-condition
                    const auto stateUnlCon=Unlock_Condition::State_Controller_Address(eddAddr);

                    // Create a Governor Address Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#governor-address-unlock-condition
                    const auto goveUnlCon=Unlock_Condition::Governor_Address(eddAddr);

                    // In an Alias output both, State Controller Address and Governor Address must be present https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#output-syntactic-validation
                    unlock_conditions.push_back(stateUnlCon);
                    unlock_conditions.push_back(goveUnlCon);

                    // Create an State Metadata of the Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#alias-output
                    dataf stateMetadata="Metadata that can only be changed by the state controller";

                    // Create a Alias Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#alias-output
                    auto aliasOut=Output::Alias(addr_bundle->amount,unlock_conditions,stateMetadata,0,0,{},
                                                {issuFea,imMetFea},{sendFea,metFea});

                    // Calculate the Storage Deposit of the Basic output we want to create. https://wiki.iota.org/shimmer/tips/tips/TIP-0019/
                    const auto storDepo=Client::get_deposit(aliasOut,info);

                    // We need to have enough funds from the inputs to cover the Storage Deposit
                    if(addr_bundle->amount>=storDepo)
                    {
                        // Create container for the outputs of the transaction
                        // Add the Alias Output to the container
                        pvector<const Output> the_outputs_{aliasOut};

                        // Add the needed Storage Deposit return outputs from the inputs
                        the_outputs_.insert(the_outputs_.end(), addr_bundle->ret_outputs.begin(), addr_bundle->ret_outputs.end());

                        // Create the Inputs Commitment https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#inputs-commitment
                        auto Inputs_Commitment=Block::get_inputs_Commitment(addr_bundle->Inputs_hash);

                        // Create the Transaction Essence https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#transaction-essence
                        auto essence=Essence::Transaction(info->network_id_,addr_bundle->inputs,Inputs_Commitment,the_outputs_);

                        // Create the Unlocks https://wiki.iota.org/shimmer/tips/tips/TIP-0020/#unlocks
                        addr_bundle->create_unlocks(essence->get_hash());

                        // Create a Transaction Payload https://wiki.iota.org/shimmer/tips/tips/TIP-0020/
                        auto trpay=Payload::Transaction(essence,addr_bundle->unlocks);

                        // Create a block https://wiki.iota.org/shimmer/tips/tips/TIP-0024/
                        auto block_=Block(trpay);

                        // Create the Shimmer Client to communicate with the EVENT API of the nodes
                        auto mqtt_client=new ClientMqtt(&a);

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
                         mqtt_client->set_node_address(QUrl(argv[1]));

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
