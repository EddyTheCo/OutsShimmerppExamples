// include https://eddytheco.github.io/Qed25519/
#include"crypto/qed25519.hpp"
// include https://eddytheco.github.io/Qslip10/
#include"crypto/qslip10.hpp"
// include https://eddytheco.github.io/QAddrBundle/
#include"qaddr_bundle.hpp"

// include https://eddytheco.github.io/QclientMqtt-IOTA/
#include"client/qclientMQTT.hpp"

// add support for JSON objects
#include<QJsonDocument>

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

                // Create and object that holds the Alias outputs returned by the node
                auto alias_node_outputs_=new Node_outputs();
                // When the node returns the Alias outputs execute this
                QObject::connect(alias_node_outputs_,&Node_outputs::finished,iota_client,[=,&a]( ){

                    // Prepare all the basic outputs returned by the node to be consumed(if possible)
                    addr_bundle->consume_outputs(node_outputs_->outs_);

                    // Check there exist an Alias output returned by the node.
                    if(alias_node_outputs_->outs_.size())
                    {

                        // Prepare the first Alias output returned by the node to be state transitioned
                        addr_bundle->consume_outputs(alias_node_outputs_->outs_,0,1);

                        // Check that the outputs have make available some amount of base coins
                        if(addr_bundle->amount)
                        {

                            // Get the address you control
                            const auto eddAddr=addr_bundle->get_address();

                            // Get the first alias output after is prepared to be consumed
                            auto aliasOut=addr_bundle->alias_outputs.front();

                            // Create a State Controller Address Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#state-controller-address-unlock-condition
                            const auto stateUnlCon=Unlock_Condition::State_Controller_Address(eddAddr);

                            // Create a Governor Address Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#governor-address-unlock-condition
                            const auto goveUnlCon=Unlock_Condition::Governor_Address(eddAddr);


                            // Reset the unlock conditions of the Alias output
                            aliasOut->unlock_conditions_={stateUnlCon,goveUnlCon};

                            // State transition the Alias output
                            auto aliasOutput=std::static_pointer_cast<Alias_Output>(aliasOut);
                            aliasOutput->state_index_++;

                            // Add 1 to the foundry counter because we will create a foundry output
                            aliasOutput->foundry_counter_++;

                            // Set the amount to the minimum storage deposit
                            aliasOut->amount_=Client::get_deposit(aliasOut,info);

                            // Set the serial number of the Foundry Output
                            const auto serialNumber=aliasOutput->foundry_counter_;

                            // Create the Token Scheme https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#foundry-output
                            auto mintedTokens=quint256(100000000000);
                            auto meltedTokens=quint256();
                            auto maximumSupply=quint256(100000000000);
                            maximumSupply*=1000000;
                            const auto tokenScheme=Token_Scheme::Simple(mintedTokens,meltedTokens,maximumSupply);

                            // Create a Metadata Feature https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                            const auto metFea=Feature::Metadata("WENN? SOON");


                            // Create a Metadata Feature to add to immutable features of the Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#metadata-feature
                            // Set the metadata following https://wiki.iota.org/shimmer/tips/tips/TIP-0030/ (not mandatory)
                            QJsonObject metadataJSON;
                            metadataJSON.insert("standard","IRC30");
                            metadataJSON.insert("name","FooCoin");
                            metadataJSON.insert("symbol","FOO");
                            const auto metadata=QJsonDocument(metadataJSON).toJson(QJsonDocument::Indented);
                            const auto imMetFea=Feature::Metadata(metadata);

                            // Get the corresponding address of the Alias output one is state transitioning
                            const auto ailasaddress=Address::Alias(aliasOut->get_id());

                            // Create an Immutable Alias Address Unlock Condition https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#immutable-alias-address-unlock-condition
                            const auto aliasUnlCon=Unlock_Condition::Immutable_Alias_Address(ailasaddress);


                            // Create a Foundry Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#foundry-output
                            auto foundryOut= Output::Foundry(addr_bundle->amount-aliasOut->amount_,{aliasUnlCon},tokenScheme,
                                                             serialNumber,{},{imMetFea},{metFea});

                            // Get the Token ID(Foundry ID) resulting from the created Foundry output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#foundry-output
                            auto tokenId=foundryOut->get_id();

                            // Create Native token from the Foundry Output https://wiki.iota.org/shimmer/tips/tips/TIP-0018/#native-tokens-in-outputs
                            auto nativeToken=Native_Token::Native(tokenId,mintedTokens);

                            // Add the new token to the list of tokens from the inputs
                            addr_bundle->native_tokens[nativeToken->token_id()]+=nativeToken->amount();

                            // The Foundry Output will contain now all the tokens ********************//
                            foundryOut->native_tokens_=addr_bundle->get_tokens();

                            // Calculate the Storage Deposit of the Foundry output we want to create. https://wiki.iota.org/shimmer/tips/tips/TIP-0019/
                            const auto storDepo=Client::get_deposit(foundryOut,info);

                            // We need to have enough funds from the inputs to cover the Storage Deposit
                            // of the Alias and Foundry Outputs
                            if(addr_bundle->amount>=storDepo+aliasOut->amount_)
                            {
                                // Create container for the outputs of the transaction
                                // Add the Alias and Foundry Outputs to the container
                                pvector<const Output> the_outputs_{aliasOut,foundryOut};

                                // Add the needed Storage Deposit return Outputs from the inputs
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
                                qDebug()<<"You need at least "<<(aliasOut->amount_+storDepo-addr_bundle->amount)<<info->subunit ;
                                a.quit();
                            }

                        }
                        else
                        {
                            qDebug()<<"Try transfering some coins to "+ address;
                            a.quit();
                        }
                    }
                    else
                    {
                        qDebug()<<"You need to create an Alias Output with stateController  "+ address;
                        a.quit();
                    }
                });
                // Get the Alias Output according to '/api/indexer/v1/outputs/alias' https://editor.swagger.io/?url=https://raw.githubusercontent.com/iotaledger/tips/main/tips/TIP-0026/indexer-rest-api.yaml
                iota_client->get_outputs<Output::Alias_typ>(alias_node_outputs_,"stateController="+address);
            });

            // Get the Basic outputs according to '/api/indexer/v1/outputs/basic'  https://editor.swagger.io/?url=https://raw.githubusercontent.com/iotaledger/tips/main/tips/TIP-0026/indexer-rest-api.yaml
            iota_client->get_outputs<Output::Basic_typ>(node_outputs_,"address="+address);
        });

        return a.exec();
    }
    else
    {
        qDebug()<<"It is mandatory to pass the node address and the seed to the application";
    }


}
