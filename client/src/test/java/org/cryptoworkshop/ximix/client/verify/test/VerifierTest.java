/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.client.verify.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import org.cryptoworkshop.ximix.client.MessageChooser;
import org.cryptoworkshop.ximix.client.verify.ECShuffledTranscriptVerifier;
import org.cryptoworkshop.ximix.client.verify.TranscriptVerificationException;
import org.junit.Test;

/**
 * Transcript verifier test.
 */
public class VerifierTest
{
    private static final int NUM_ENTRIES = 20;

    private static final byte[] encKey = Base64.decode("MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABLIZ6wtfuFzkk3/GsWRNkuMHJ9Ye9B/lYa+90tU3bboZO0HUY3l2u2Z7W9Dv4UhBWVmXOU91N3V9It54o6dCtVs=");

    private static final byte[] witnessTranscript = Base64.decode("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");
    private static final byte[] initialTranscript = Base64.decode("MIIBHQIBAASCARYwggESMIGGBEEEKRIm6FcM6Wr7f9uCtKf1DWQye06wPZveQc2/HDbHgJtTnIXX5wKrWa4q+BLF8tTvj2QFUfXYjkGttVgoT8ZXQgRBBOG/WVtzQ0J3TL9mEE2KgQyXlgl/+7sUHlQazBMe0t6CyZfoLzefrgoxcqGgi3zxElGTiLFhJgj3O8M+yV9X5p4wgYYEQQQpCg8XBX9W/FNyRN2Ef8dF5oIyPzbF7Wz0HghR3EchwZj4hjP+HB04SAg8ezq8XqaUHqidUFuw0Yjmgw7G1JMpBEEEOS5cFibjwyF2l5lzEdS7Efi8vatKQIUSRpxB4dvtF8bhM0ynDWGzItTvZmnMALsI1CZjZt6XR8qEH6qLM7cDyzCCAR0CAQEEggEWMIIBEjCBhgRBBPcUzBRumMD1B49tHbPm8+8AjnWwZjrvFUoDbrOtyx7lwk6TPqy/ZLN/jWamTzIkMIQFR8RfjBTLtnWgA+r7td8EQQTXiVYFfMeoowgcza8jx8UMyaOF/DOPdaq1x7LLRXZHKAY5BPANINbXl5Reky0vSL3QcCndj/bphUdbaw5s6n3jMIGGBEEE3hzmueeEBMbzXmJ2hDW7cNh+/eBLgDdnecQbivVGLRpQmmRL+iTWqjIAAvyTXitpfNq20bwgBE92bLhd8FX0RgRBBM94rIKY4JJZj9zsv9RCojGAMqB7qc1ciqG1OecuUUkqzcx6TNCd0E9DOSgTXShJF4pzbVhWcKKMtPbHxyZb51wwggEdAgECBIIBFjCCARIwgYYEQQRcKFf2rG7zmzDVCj0EQpL+0vgqKZ5Dhiz7ZTqs8xt5CUC0yCwWad5ssLNUy6nq5IrEhp6MK31jjLvsTJrniZQ9BEEEnbXrpKwUkBBglOfcabA2lK/iH960bywJt5NO5AYVfVJpXoVhXPagAWiRRxq7Uq/9GwVkZgb1yxmYb9vSkdhddDCBhgRBBN1K8dIh69TAtRhZWiWnGdWYCOB1PtstbdJ4EWc9TUkPgN+qsxrZoIv/DzWprFE909JIwJ3PRv3WKgNLcJNwFJQEQQR+9bf3ekd7adhfpQ8tIzSFEXCinHX4jPv2rtazThK8bLPxxljjfg7bU4bBB3iWQDXxqqsFcmJNL5Oqw9KzH2PvMIIBHQIBAwSCARYwggESMIGGBEEE5ovmCp9MZ54FTtTs9xGQkOB05WznSyZ+a40CnaQdBqyOgYaFjGaZ2R6eTj2E4sI6bL3KwxFft65nAeWbmMsaUwRBBEjTNgPlFCiwYQ1pgfkmBTYNDHwaUJwMaJzp8KEksKoslRyTzftuNlL9TptCj8ewomYQVcWzTZwz193wh/FDgeMwgYYEQQTV1ukDmkbTMlcAs9nwtWB/2UL7BC3OIdGGBqfTZvPbRbM/PAGNq5RKu3FJ9NOVqaTzcouPAvhCjYiFaeT3gKuGBEEEhReJ/t34+NyrRXi6UnQUF7p+Qyo+8v9N3n9RKAyoSdubcPkOYHTDDikPCGiCTpO8avN5MjK6eixm1ZaK+vSz6DCCAR0CAQQEggEWMIIBEjCBhgRBBCkyyLmP04e1opw7CtZzMy+WVwmgpN0mZnmlf7yrXLDT/u1DfaHVg6IAgM3zqwvxkfbL6gwVtaW3b3YqlYYw8wgEQQQlSpqs8w1dNSjfOR/iHZ8kLkagKGTWonWatKVXI5MgbAtZh7uy3EPGXp5KZxMHBZdfx5C6EHC1JYN+52j9clKMMIGGBEEEPhrLQmzkMr7NhFN4IvrfiOgiIBgNE80rKNQF0HabfjnGuhwJqcWjrCA0Pz8mdU1jEEVszCX+hKz6+tdvJjt94QRBBMCCbHURrjcbJKhMNV122yZxOqIZmkbFV1N5TpbXfq//tFdhc1BvCIsNN8ApTfI9E8Y2ZgWjHBpBYHwrd/Kf3vQwggEdAgEFBIIBFjCCARIwgYYEQQTAL7h2qj1BJqtbjt2Q78e3BSBeM9gHNYAYBKQ0o2iKGi+8tCGECjWPV0sxT2x62nRtpUAl2GrIv9QgqJXpNI08BEEEqrl5Me8vcERh6unABRmwcVZ5qYZ8RIyirmhdRXsJtYZMoJkrTnpGYaYRUIiN/zhvagNZB1wOQAyufJZnqX8xsTCBhgRBBPcp45Yo0hcFswsGaQhy20NaK2I9u1cC2KBozvgpP6DSmRftqiRxDXj7qWjOsiCF48ASEFWrOWmSMZNO3A4ponQEQQSwT8m8VJ/ewijkZcYoF6F9kwDc47fD8l90U42N0RDZESC5SzQNbUVP0hNwcP/wrZfIHv8z08+s6oRuCOsH2H8dMIIBHQIBBgSCARYwggESMIGGBEEEruaesvz9rVCF5/vyoge22oMOB8Ni4wLWqxPt2N/Yg292mia/jhgo+pKnv9WR7rg8LsU4AgJzI8AQUtLVoEcU9wRBBO/w1gx0fm+LGFn//TPWalPtQhqLJEIJmgqBaMjq394ymJZRhaWrBsdMEvxAkTqCJ5GJl9RzD+VtPeYRMPFTCIcwgYYEQQSxOxSpMhKT2oXySgQOqBdGHTFvC2KT3lHOdtTPL3UKDeSApMhgzzfKdE4sCn7ttHmH0l6ww3cpnHrR16z4mPAEBEEENFoQxxU2P8XXrcLjI7UMUdqSU8NEmGZgawcY59yF4JjH8R/sGHyjiMBIpcDy03SvDd4AKmIIOmsE2AGFTYW98zCCAR0CAQcEggEWMIIBEjCBhgRBBCCdTQxgE89Lhx70xqVXuOeIElsvRu2g88mpP56yC4LWE0t0rFprM6LXRATSA0+u4r++t3WzeudSRM0CjO/3j2AEQQSoxgEmUMEWbiyyZN5Vm6gmATXEbIbHbXaOJRKpdeVXNidrYy+p63j6ieWIctrQyHbyqKtMqCDK1uOYVIK9xH1SMIGGBEEE8ohlxsFU17rn1Yyw8JMBytEtopf6OjuI9rZNfgosk0MqVaqM1jGz0wnarQzRWMWELerGbQ5YSHln8fm8PovIOARBBNV+S3odaz00LfMmrOYlw5WZggRZ5PbV9QWoeDCQLSoSPzdgQvqucXnKsKEcnM5jsuvGHjs1M7IFzO8g2bsmRskwggEdAgEIBIIBFjCCARIwgYYEQQS6dYepkQJFEv56jBLrWQTyEXC/rIVo17ilnR1DSmy3UPBJtq99S98rM7FZb5u3Pa8XzMOdiuoKDvrMaRXf0WKABEEE9hEginNZfW9d0WHG+JngaHDVMJeWVTTI6kSrLKje6JmLNTWHP5fSGmV/cQph18g4kAYgugE+iieT+FFqg/4IWTCBhgRBBBGvpYnjwYNoM+crWCx1JH6QYY1ommynQfbj0wjnVGpI2CHjXOlMEMLXC8ru6XGj0LE9K0NIHa9pUdhiy6WOg5oEQQSD9k4Sv/Jl2cCi0EMJz9uia9olcvJ4nJElY5CqJWk86ra8/uABM0rhTG/HCUAqynzGSdsvup+3vPNmInlOa/L7MIIBHQIBCQSCARYwggESMIGGBEEEU5BzuP9qLUPGaeP2QSVf2anuvwgV5zSyg9jcPLgGfb5J7biXlQ5VkWYbOqSWSpWH8M564qj1gk7StZ27yOfAHwRBBHyRDL/zwE8fFBrkBZ9k2zvNVmtu5UlIG9MboN2HJNypXcu10TpnP55k3KT09D3PvWrD8pBc5dPLfsLxaSftxaIwgYYEQQQBbgupY9/xfOZ4obgyOBfvfgXCYdEGOo5Pw/aJP25qHSNbXGvI4bihDWaf68Ww3jWwFhkJBkpsM6OBUqGuKXaqBEEEfkd5e6oBnY0VbLTCUKFqLggLfP8W7ZyCrd5fyAFp8DiCK1gMY8ZWum8vw9SSM1yL/lSluSE4FqQgVGk/CNpN8zCCAR0CAQoEggEWMIIBEjCBhgRBBDFqw8VQs7GQFVndFQN/+byJaHwT1v0CA6eqSOcXWhubpFgxtrF/WMTwrvFOF28rMxTBgB13U7ISh2KMis1ituAEQQQZatIvyUvbfjtcf9C1ed+qRKJ/QZk2OMim4dd+HImxiRjohJ82lviDu/5pCK+0SbonG/DPN3Ya9n0h8WJD5V2pMIGGBEEEDAa2J7YzmxdylweWhUF8j4+0755XJrN4dRPV6+stUQD3K7w1qY8uD+rdQ/RW1F47wVLboNwNM4nrg4JabgsyMARBBODr/YwgfSji0DnJQYCDLm8WoK8VO33lsh/WtVA+dFKDLDPuzQasngJzZl3jkyiDFOeC/oFBZ1TM+Vs71bLDM+cwggEdAgELBIIBFjCCARIwgYYEQQQGwkjuQuMOmu82lESwRIFhmw71dO6fT7wm7SUX6mqxDCpY4oNlwNewC+G5mbRGQHv3MjvGainyGujCOlJOiEaiBEEEnwspKTskQA4Xm0TQTOh/juHt3hz4YhpHwaFT6kKdPlrPrRz54YiK+QTiRXtp9Eb6Q6Kwy00ji79+7nP/QPQnNzCBhgRBBOH2pTDsj1AOgE5ZodlhAkvJC99pNBy85OT5pCgS8G32Kbocq5Xp7aMMuTxqGs8BBQLgPqToFM2oV9E/UZaTtOwEQQRSoeCHEHX5USIuyevO4oPrW/Ah4LHAxUfCDMF8j3Evs37CSHKzukWvGvJhDB3hTCsAjaXthfkSpH3uWwaSiQV3MIIBHQIBDASCARYwggESMIGGBEEEoKIsBkvxUhmAcPI50e5d2JT9nTy4EV67tSC5Fz20NyROJCHX8EZ7eoGxzmt1X6QxIEIjmrNfiDzCQ33pUV493gRBBJBRo4QVv3pgV19Z9jFYgT0g23/xkKApQ616bdBgYIVqjLkVHIRkY7v5lagPpcvmRF/J5POpI0dx+IbnyQP2RRcwgYYEQQQml0yqLeHHP0qBgkyKw2kZP2wkPObbkJpY6FhfTbT5bKZOvO8VfRv6SZc/pFHBRwN365Mmehm7Sd6cmONALR0mBEEE8942kaiiltc3XAtaNS9J5KEXygcXDhkxOwjx+W0FDKUjmN80JMgEzFDkPpnHTGkaQeeFGyGia1xxAYQNyrDHaTCCAR0CAQ0EggEWMIIBEjCBhgRBBIJMerVSF0A/UYfN36yOeKTBSeeCdpjkuN1BJrbxEZa4T7t3YTERVBDQDUp+pQOk+egXvO1YsaReGbCBkrvDKwMEQQR1RjBEP17Jja4KcSNWBeuXFxetRHSpFgNeg+dXZTEAxe+istnDejHdTMhHM+wjaq6S5y5zocDMfELu6wkGABv1MIGGBEEEXyU6rV008A1pPW3lgeq1f61iLbwEOsuH4FXe+1S8TCF4RSQ7fbmXNwlTr/insGF7EVp4JpC1Hihwic2GoXSh6QRBBFMYMdKMae19uwXCdk5h9DuSGbgm7lFMQUGJrzefb4Be+U8+BaEmfmoSRg5RRmlZ67kxvzwKvd4lJpcDT1tJpe8wggEdAgEOBIIBFjCCARIwgYYEQQTpEhqDw4Gu1KEyVrn8YJwwUzhCBpBOmLQd8q5idiLWrOibTYKXCrmFb0Xf322iwluW510WRP0Od/UmOkbSzSbzBEEEyQVNm1C6fBWsUa71N72KdfcbaC7QTuQT3LKkaTHmQjp7nEoK5umydtQEIG+QVImWUAitBk/4DQIAmkuUx76sNDCBhgRBBPdLAQ4wzAC+k6+2+HseuU4gw7X4ZByg5qooBs6O1AWi2PiKAKSq4rBbHraTqr5/E0I87NheL6FtIpg7JAVJ7mMEQQRheZeMIRXYbUD+MXMmtaDH/Pd5fw4zNBtkgcq95mAdaBEAc3zTyWrlg+MipecXWd7SE32jjvuDJHy/o2WxXrqRMIIBHQIBDwSCARYwggESMIGGBEEEh1V7bZyT1OS5Cp2MrvgH9KtU/CcFY1y93NiMYQT0jqwoT6jNyPbDGuDSWiQ/Qt/T4eAWLxctflC3yUg8hm16VgRBBHfdrKK7o401/DuVsdL/Bx3ETgO+GnFuXFyHZc8K86jmUqqn0q4b39WdhiA35JOgn7g1GB3NtpaD6QcJhgiWGk4wgYYEQQRjQ1T0/U3V2ROsmIA2T+i/HBvQU306Dh1DsKZq5+1ND+jcJxVuR44RzozMeg+2lRBVSZ/nLPKyMdf+nxIYGPABBEEEH64ykazyti+Cfj1mx+pBVzt5BECwEzpiYuSbecUr2fPlO/yGgWorpClhV7sGoWmhyZz0dIpAsUIFbq3XuaTxPzCCAR0CARAEggEWMIIBEjCBhgRBBHx9KXMVvwmzxJ2K4fgT2Jq7oyOH6DLSi6LbcyeyanHBUSWB4d2uRpqYzTAAvCWgZnao3oSOxNuKO+QiZju5bC4EQQSu8tI4E5jGRO3VMijy7XTHfhBJb23FzM4+vyQqcxtweqXhC4KnjzxydQY6t3DDSO9HhhqIvee1Krotmi70ewHHMIGGBEEEq0GPa6vIyqA4mD6qAMyd5Saek7cAC/VvWEtity2DS96nXWHGZV/cJGShFL/Ek0vREYmg1Ya/1ZEy5u5MdnYXPwRBBDz602NrApwUWbTX/lV6TPVH2DJ/YKRtgwsLc3oqJhMPjCPxUwMGb3mjJpBL1WKdHLrHqwnqeLmkBPkqzLfEOAAwggEdAgERBIIBFjCCARIwgYYEQQSHdqx+1USNTnZ9V2yEcfT3LsfkrTcsqHrUJ+fXsIKsSR/CjNkJ3sUy6JAP61dxudUaJZanLS1vASs799k5PJFgBEEERyygB8P0GtTwUY0588DbHhmc4Smgj6okpUhX/+fZzQKnUUvaEqMyHcr/yOrc/U7/TE1L7/4bK6ZR6xsg8QqFGTCBhgRBBAnN91dc1kpOcZwXlcSKCUXKWY5WsY5ZzQYCLg+7Klbl1lIsI8sLNucF8aHGeBhGMZPxiNXnekwyoaorqflsde8EQQQvr4Do3JPS+azfCNkJUGf0iqSa9cNJ+8F8/1HYFxqFt84Eesbsyp45rsDJEMkQPwVFA5U5duWC5IbKfUTLVXu6MIIBHQIBEgSCARYwggESMIGGBEEELKDVIqEAtbdcvWlxrhOvuMQZR8cdqeCwXsWHg8esH8swH5FS9/XmA/oNU+xTCpB0OsdpavYrf1tirl5nR0NROQRBBJ5LqbQcQqK6ONq5jCfC+IMhNUnp+WLKIseM5NPYgVaCVbEwGP0jBjczNoYdpj+lv/zaF4VmTKhncF01JdRVBIowgYYEQQRrvaADrBe10gB0karAP/NyAWovuZO0lQF77SjUvHMcsYQ8BxUQA/Xf+bOABb4gNhdngY+7Gs5r6YBfxbqNAJiNBEEES09lBbG2hTqUcAzWQnaOdO7NwuGXctnTcaReu7BSZW32PRZi59JSsAKKzKpW4ZVGsfviff1qF7nMrpWV6/LXiDCCAR0CARMEggEWMIIBEjCBhgRBBFf1pyBPAtnSxVRgfknGJ9TFdc025Yqh0lB403nYuzWQ0G0A6YowkizIEVpMaKvWu67kFKjH00YSM3XuXgIjpyoEQQTurUIifCyhEftwUmpvPd/E4noWjv/h7bXDiybzt9wf9rJluK1RK6xi4dNsXL6p0heG5N1fG7b/tYyQn8wRzIPtMIGGBEEE0DghNJVE3A64RvooDfiTS0lrbK31+3entOFv++ube82iZ3nUPNCXc9i712rzVDrTH/8uwbYWmcrssKOqoBbszARBBKbDd/+If43eKeAjQPT/X5AE/VaVnZ662aPT88X1K9Q0SCrXjLLD38GMOQ51LWsN8qEUZweRqWL/2KfkqR//BT8=");
    private static final byte[] finalTranscript = Base64.decode("MIIBPwIBAASCARYwggESMIGGBEEEw7VCzr+9k5awLl60CZQUveIbGE9RnsUu9MhvQqvmU7P/pTpfUejLGNkfhYbxnA5V8CtMVyNAPbBmhMDaqyMmowRBBNdvEgzX/uFQeAPYv6yk0puzLInXVJxFx7rUbXkDPPBjrNy8G8XguDKwA83nZ7e4hrGzqfhldV/s6CCQA+e8H44wgYYEQQSNoLCaQbWAG0U3HMK/khIq8ZwrP2wMKiK/qwbyykH9k4oqMGKDGZu/wFzS3jUAP5W5nT31SLeZ1Abv0iQDzzk+BEEExlNQnWStsJc82QjJZMXHMf/Uqogbu9RGcWnOxRUecU9tW1mryugmp7i6fTVXsdjdkF2DZSILG580xD4fSmudkwQgOY0IncIKijRiaQHasS5pPb7en7v/B472f98sOcPG5zEwggE/AgEBBIIBFjCCARIwgYYEQQRZOGMlaOAmTC3yrnrgYE/tlBNHqhTiGvAjxwVGAeQ+DCXGxLPaHWyrKJSa0bN3lr0wa9kmilV99XTAViQ5SsEkBEEEoW6GgehdqK489Asu4aJZ2NVjsujVyHoS4FKK+SHs6PYLnoK8gC3oltdBLe6dgLbkj63dk7dZOuCvR5BwKidOWzCBhgRBBIa6vOnm+MxqoTzcTzpr56/oJax2bKg0KFYhuxGhT6VUT2OCuq4wA1k2hQFR3YFgCjvHRn6h3TsYx0vLagPXlF8EQQRoxGlu/qKI5TJpS7MglnzspWE+dLb9FpmWVvrZdFndkKexePCcD6uXlpbPeceYCrUwaMrJCzkUcmyFEhujI41ZBCCEC5SvuPAQOObamJ/1IB6KO9uYxu0mZnwNzXL2gi88bjCCAT8CAQIEggEWMIIBEjCBhgRBBKhJJ9bbifv/pOiqKXmtjJGuebuot4vZp+403PcOOQYIq/sQySFrhhfgfjQ+edNVT50+NfLbQFomMLNOnac4+9AEQQQYTOkfFrzrXwg+XtZVpYODwKYF7chsT1y6O9yxrZ+XFejYST7UqEdwpEzA0EOVUzN2/nzHJR+j6udzVo/w8GhHMIGGBEEEB0nsBXwYg3yg9mkNHNLzCaBgfrPT1HTHCpIVpoBMljlt5JSKkbQpWr/j8I1IGf4fCaHXimL3HTcqF5g+ynamxwRBBJpvgWC5B5feaMSxfqTcI0feUqWxpKn7y+/30Cp9Y9cbpq21pni2optZiXxDNWTkeHtp5sQA0ayK1MFMMryiZ6oEIKzFrD5WGSXsnoVlbH/gdN+em87cuUXEgoxUm5/5Ww5oMIIBPwIBAwSCARYwggESMIGGBEEEdi8PIjADFtiOvbShroXRA6pt40C2RZ5fHC/4HN5vliu9wrrRC3Rfq+GNCfDr8fslFD4/sa8IqTHzHO1vboAmUgRBBIZtSyX7qVQ3386e41DOqIbMutLk0U9r2s5gbkfun7rwmd4/nzI4CDflzxctfst78c4wJNctDI656fR+Lut0WcgwgYYEQQSHYsFGHDx3LlfSOQU31TuZSoF9WPsJy4+f7jSziNVgRynekBw2YfF0uXC1AQFTdLG+1njSY4J0bw7n1BQe0gcuBEEEPDMHdj3pG9jXiVBBZJ/8u4ImFumDtZRbsun23YdVXClLF8yn8ks5ngdfvYSM2ghGXEBQJH7ea/gg1pkWWxBQ0AQgcHXVLovX8nI+kGDVE0j7dC8FT7jO74ux0WiLIgQ1CH0wggE/AgEEBIIBFjCCARIwgYYEQQRK7tNJ5fp0gqeRhPaN+ufRr15Ydph+fCPjvlLqbvcXFF7pnLXgZWVREWBcyG3VVC31L1uHDLoTqiZnIoaoziGtBEEELStUbiy/zQT3n47ec9lwTGlSMwY029ctXRRE3aCT/b9vGiEv9Jv1i6JCmXUuP4WO/qkYqC4DFlrCDLLraAA7rjCBhgRBBJRgCJr9/PDYrcEIf5vUDXNaZVRLo7UT8bUhTuGW+JckQB7y/oGaySOZ2LsFm/k44+fK3fSq+NmHPftmsaCK/2gEQQQzA5wRKY76iNeC6pviefTsXiatTCcvvkk5P2qadVPtHMguwoAHHq4+irDIHHYQSN6nduvXN2DuaPUpsGNsY4sbBCBh0Q2vrvulcW/Xbf1G6uz5mBexm7P4iysfAh3R/VOaEjCCAT8CAQUEggEWMIIBEjCBhgRBBAzy3z9NVW34owgjDmx4+aL7997I+fEZ4hjxVNvqK9wsjD7G1NmVNQmOAoR3CPOr09JVac6iYhRVGjm6UrNQmtUEQQRFnAws9XLO7PxYZ/+662Pocp9mRGfioa3ttOvry1WpBoONADdyfROxHAzNS+xgONM8SSG7OHAYaNKFAIdp8kMsMIGGBEEEFqlS76pi7efXxQk0ULOi/abacJR8j/W7H09WABnNFRdVyykeZkwV73gBrAWYv57FWh4BKbzPxvoTaNXmzkyUmwRBBKomyuBq1kIBlAzjuK7/JXNffXRktAR3v0msn1PCC98Br+mGUVIuQZ7Y7COL18tj1LAcCBcqDecRryHESI/0NAwEIHuardqFFmeWr0ay0o6RAUom7cAhMvCevPR4FjkKj1HrMIIBPwIBBgSCARYwggESMIGGBEEEsKjjpdr1vusLb++7cZas72ojK9Gq2OysGXJMTd5uIhRLofRghk+4esadnLZNysdGlo0Uuzvcynb9i6NV6ZmALwRBBMFDbDEl0K4tcJJOPHkWDqhlL8bIsNU2cYFo1bXwkvciUe3BcPFbG8JxSLad5U0KUBgBBjdQD7J7tS4KRZ73i8cwgYYEQQRjKQ61VBxCO1MrdoIOHQUrdGbNq8llGWTkH5XxYBT6cyu7qM/KnW4KZwed37PNu/GuHMgH+f6RdOZ/tZXq18GwBEEEg/PEhNWQtBT6IoawRoO90rNZd3RauQxc9nL/QmSlXwEbmqbh4CZUbKWiPsMbRC62oRn4KiMEnhUYCPLUCSPgHAQgrDDJv5uARINC82OEU5DyUhmL541HgA6vSxA1AyatKnYwggE/AgEHBIIBFjCCARIwgYYEQQQwKfjzpK7qI3Fiq1ntIwBoSLJpQsuN2CfR56gI7Uz+KkgAnS74rAOULODD/SDoge7YRQitZNsv27R8gX+CymJNBEEEvV2r+aKb+h5S/Mgcp2hjzEnPUNS07LsRh2gWWO1y0c8r/8LrGmMwekUgQAqpFG+2G9Uo/T7cTWRd0bDK5HiBvzCBhgRBBHDrSGhc3aYaYuX6/2rcxl7gpGAUc8A01MXPp6u0C1xE2Jwn0iEFKSc5h5qVC+Mz9OUTQwKIxsgaZivGOI0dc8QEQQQ6dlhaGASN/r2R455mncg3nSTKGupo4gjmoS8ikFNW6FtuvRqkJvVUnBSvXJi/MXELWzpHHZm80RJFaNbW8cy/BCBdk2mYUFt8728Cv1CiNQrDcVMa/9x9dMrUJWX7f0MxpDCCAT8CAQgEggEWMIIBEjCBhgRBBFxNO45Hx3mS3kxeoBiKqxGU7rbufMPnAaGwMivbmqu6OzTsfX/Bq+LlpiCeQ4pGuOPZuPVkuzt7oFmznm9JqSwEQQTj0d+6fMfu4UaBNxXuts0d6KiOnUiUz7ipxy6lMlzFd/omQO3S3LnNJL8khvS+cKE+V16YkSEvtGZv+pYyRbgdMIGGBEEEbm3a40rA2K75VRF/VmxLE0YhKneR796jI50y0ytIxPUh1ZLCrc0KtecgrmwX5sQo6FGgctXkMN9UzZUFIxWSsQRBBNJb1VKgPluRDnBA2hSLJGS9qA/w5Yg1eVWdbZXR5BbNHXrQTq+F7DfTPaxrtsFWOjqwoyoP3io+2RaTKPDKuKQEICwc2X0iYbNUu/P6DUS0CZoVjXXni5ExtnjLAL7DoW8SMIIBPwIBCQSCARYwggESMIGGBEEEzup40wYVXmQzKE7VSrdEi2NYi5pKhvq+ZNY3jczawbM1OziAOMzav5butIMnJkWcS1E3jbbPmNpym6tpJb9uJwRBBJu9AWbl8DaMrF9+Rge4oIqayx5orQewIBWQanLVGFzAcAU2XwiIG8w5QhiEdhGpsgjt1Fl/C9B7A0V2xaSLxaYwgYYEQQRjOXZ4DgzOI+FabEbWuQh9z4ysG31phYQU0vlAJRGhfIT+bW+yO3dMk5j30IJg8MGA9QKZotsX+taJUHG3eczWBEEEqrDk6fO+6CQntQ/TlbWkZfS52axYqqu/MfG5k85ebeUidETQ4dpHDfYczbxO9WzIKAHh5ScoRqTHGyCbfpqkRgQg4x+VxCSN042B2U7LaU/wmgm3qQ0/YgiVUOSPGlLSXxYwggE/AgEKBIIBFjCCARIwgYYEQQSyexVrjXDLCk9+oHfQYwQ8T0m9S2/dm/ESgGUMTHBbE32+6a+/VErurTVx6/pFTCgpKIkXfxd6mm4A17cEFf2SBEEEy3N1e13mkTTosbyvqOVZvcTtHMZzA89lOrd29vj+jQDJF2oayLbA9pYVmerAa+u/Yd9evryf3vdZzoXacxLrBTCBhgRBBKDzJQUcOsAaGcJ8DXNABVek+Dv5l+z/5mRAGqbwod7b/rA3S+Tre7tng9zrrvussDmNzqbkc6Sc7HPXJdOexwUEQQQv5a4h5+gfP+gLxkUHRnOjh37jWqkE3BRDwtvzI1L0GdUjn6pqu/dT/vYK0pOhUVeybbm8+H/3FIPtVhkLK9fxBCDzCQkLaJ/Qx0bi9dynI//jV4ed09p6jSU3lPhJjZq8OTCCAT8CAQsEggEWMIIBEjCBhgRBBKtYvb5rpxc+jzULOr55ASd1BRpJNEvtt19rOOfa9oUkBbbZh+E7dbCS4Sgtd8UsZ1aLqcyvAEBXhxiSwpwt5/YEQQR8O6icetGqGTaCCoyb+HaU1w1nEwqPUTeIEPI1LhpDfkkgrYEFwjNcgDRz+JvV0XzfQTuRB3frPEABbes2AnROMIGGBEEEnGewdB10046MJBTHAywsO+y3dWWbAs6Yr4fCZQiy4VIzWgCvhAC6cKFzfncKBh2jqJvC2OmA4oig7ZmGMkdurQRBBPq1H0PXEg4J/z1nP9By0FnyDAoId6Dg2EoXflIjPvbNiR/xf0ANnXq1L9p/K0qTU1OG98mw7PCsmNm29G7sG+kEIC350D7Xbisqso1IFrxOpofJuTwrC+WTWsys7LThh3zaMIIBPwIBDASCARYwggESMIGGBEEEJu+KMCpZg88BXxr9ZRgYOLEZYZMUL/q5W0BhlmxzdaKJfmSRBm2pvc+7/yju+W6f1EX5z1sSHZhfKtWu73+vHwRBBD0emAFTbu8gsiwCsM+H/io/gfKnMY3VTEADVInri5Q4taa9VcOQ/cGXLVMnsUNYlI9Yj+5UsnuO3VxeAVnpkUkwgYYEQQSsRJdA16frA4PFL/2ymONG2AhnPaGcwsTIvj64PeL6MHAaX1llkmXqKxBmETntOCQkoGdAkb9OTyd/j4qDaFqzBEEEjx2B9nC2wW5mPLaDJNIVz93iHTDa+V7LJr/06O4AASipV75+MMAxDHlfMXjzUD//V2K6/VMevz6FNFMnpZEB8QQgmNzSIKcQnAwTczDPP/qoJ3ksqqDZbPQn1dwtMDYPTDYwggE/AgENBIIBFjCCARIwgYYEQQSVYsZN5qRpM2Zs647QjorJ4+4agPvrXNYGgVG4gnU3u3otbpqFVNlPE7sqKqGOyhKlBoEr+xG1/6c2ZdMboHscBEEEHVeXShPWBJI1DVo5Q1wXD1cWbeYBupNLkpLk+tsZZiDGVCUVRyfzknVDxm6amKjxQwCKFtdg1t6PdwL3JpIz7DCBhgRBBJmYbF0kmtszrG80y3SDqPmccVKFLUn9D6iREF3rD2s78i/R43xiBY/LYLZmNhaggCq/e1yCYcVTFZLydtXiWCAEQQTLwpQ2gSiLuIBHpujiR3zogUgDiCsXT2cMWy1aGCX2az78X3YqS4yYcUGxf4OYvEmE4OLanuq/sifs37ShkfPzBCAzzg1vUykUh+ff4zdZjcyDGQzAdKxI4eZ9qPdOEEevgjCCAT8CAQ4EggEWMIIBEjCBhgRBBK10GGqzUManSOKuTg/ZHcyZ1k7wZa5YPLch0YxL1UzsoAF/9p39fJj20iGG5TFvnbftqvBN77wl+G9+NkYoCHEEQQSsCrAfvHLPrs4afwyiU/kBgV7Lm0pjM4FSmO20XBeqPhW55q9mdYdQhfRJdqT/AqB/tQJ+GeJYYnADPl8eNDaaMIGGBEEE39QQj36bQrxHBKE6/jEJmciIGTsDLx6KT7rB7u/wfKWsQNne05BpbYeXKoS0LzQul+UEZJrqj8MTbINyFlf1XwRBBBCzOcSmG/arNvuNdjbz3MMhZtunEAIEBMPdj88B3Cr4krYF0ToDqgGynSmYjSRVPrvVniUWVjG9r5Mty1mgH8AEIFzeXDjUXRd28UaliUXK5QqYkpfVUp26odaTXqDkicbaMIIBPwIBDwSCARYwggESMIGGBEEELURN9UWVicWwkRVuKElm2QgT6I33sA9wLhrelOVk8v3mLmr64mYgPiwHxxXI9Wnr4kPw1VUVMvUJcJooqTvQpwRBBEXe0nJio+DJuMwpGYucWqEOj8nZLNXRyLQ6iGAdZ4igU1j3SZQTzJCDCv1BoGVkdnvwfzyUMDd4GXJmTeuXmw8wgYYEQQQIz6/o3XaIlSmrfbRurS6ovP2nmAvj8mG2mG2rqqVvAfZbuqxT/JwgjCxCItfXqdyw0KhfumTC0ehvC0bbeW+YBEEEGI49on7sIjeDgfdhdaZ0YJhQ+1x/QV+NXssao8Df0DKKmH1KU55Eifinvu0jbOoSWVNhthjq6Fyhmi8bcOgdCgQgFYvXH2wrFLf2UIM93gC5m533rbVCqsp0mcQwua0WhzowggE/AgEQBIIBFjCCARIwgYYEQQTHoupJLyu8A1bqJds7UjtcFt1feEVMeUExnbFycMZ4LjDMflOi6VJYISncZFKoU/HQGlKHeMlES36JdFbT9iO6BEEEvychaLTIgGWpMszo2QC1biaS2Aue2jcKF5OInw/J0mXnIIZTTsR3TGwoCoPeuR3GMHg/Y4msh2oXk0QSU6GjJTCBhgRBBDMq5GNT2nGqOL2OqXmEhlr8MCrZT7luMrb1FB+txGL8tA0ez9Y+aiyx/4uV2auenloIUui5W3VDfbLnPMSzfjAEQQTpbl7DuGD3NN/mC7VqqZ++W8NOEHVrH1kbi+PEZh/aRQ51wwbLXAFkZfdLe2FyW6qjDu4//Lz4qMpLdumb9AiyBCAx2pLCKR/edpM2aZFmP/JIZe1PBcZExMR5r2WadU3L1jCCAT8CAREEggEWMIIBEjCBhgRBBPNbMxdwzv64gTHyCNAB4glqFb7SNct2fc/2mT+kkFx8CcP/mztNMbOOXk5fz8ecq2OI+XnCHfBDMqcKrlMmDNkEQQQRVrWGTwpNwRMR8gI7D0RtsshnzjGiBtYK46MDSIsA4LggzlPwfDLXtDJRL6VrBZdQJHwzYsmNRCxZOK9oX5UbMIGGBEEEweupvdSHMVpGU6LoB09/yyeQARHDxz8xM1fTzAp4HIL0rEPJE6FPAjpxtUkoqRRQjhB2VpNSIu22CU+WN1XSiARBBB15MCiMJK4FBtGnBjzpjiVHv8S0qOmzJJ3T9kBBHKdWtffTreLrvjyXoch+A/85nWJokHuxpAXjbQqfG/8NY5EEIF19HzEDTuX/f8N+53fAaL7LLGeWgQxhniEWVrBgcB3FMIIBPwIBEgSCARYwggESMIGGBEEEFwqMQJaS5br7TIoUCGALQ+T4InJlp57akEnDMf0B6CLYWIFatc00QIiCctlffBoXGka0IEfUJ8OtVu1ExTuMYgRBBBqjT1Alljq2ULYFaF3Z0r1AwJrTij++/QljDeplrVWI3kUQUGwb9sr8QGqMN5Ozok/ZZw8ZJdYIwAyr0HHlfRcwgYYEQQSJevoNljy8bvOUfCTsxQ+EsQhjjYrvpj2nee6t+Wnqm2WwuvXvwhIG9tcrnOcvCHO4nqOR3Bg1D8HQ8JM7sQ1ABEEEFXtKhUQ4bKZTG4dxOATq5W39gh93sdEiSFGeoPhACA8QHKTSbKIld5rx6CUuqOhu/5Opx9Bj5IuRRYD4+C8SIAQgEdIQKhZjk+5GOOaWVeFDTLekWThLbEtXxqlP3ZhtYc0wggE/AgETBIIBFjCCARIwgYYEQQR8HR3xj+8+oK9n6lz7wBXPE7NFPkgZWoO6l6zx5CWBJiDsKxPBj1TJ5QHvRVghWG1DIBiwIGBH210zS0brbhS3BEEEySbz7BxyR0YxmcS8jFGjgmoMxwiIgC3Dte9mc5z4/6OrfENpdiij3fY+3kB67u956RFh1I/RO3IRO9YqMJVBKTCBhgRBBJ+ann5P/mBWVGvgAFNQoQPqipv2Z8nycMieORt7k7pJnj3y6EHDvUSOASK08FP2Z7vFd0WhYgzjU5zE/j3iQi0EQQSAthnU1TRGm96HnZlOYWBlGJmd/tEx+h9Kq6s3yMRTiaxfAo9+owQYciJpfM+rh1MEmTQRybhqTdegyvldwAabBCBa5vnqVSWka3hTn3u0kx4YAcwLHCP/zl6RxoYkqi/r9w==");

    @Test
    public void testBasicVerification()
        throws Exception
    {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encKey);
        ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(witnessTranscript), new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(finalTranscript));

        verifier.verify();
    }

    @Test
    public void testInsufficientInitial()
        throws Exception
    {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encKey);
        ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(witnessTranscript), new ByteArrayInputStream(getSequence(initialTranscript, new MessageChooser()
        {
            @Override
            public boolean chooseMessage(int index)
            {
                if (index % 2 == 0)
                {
                    return false;
                }

                return true;
            }
        })), new ByteArrayInputStream(finalTranscript));

        try
        {
            verifier.verify();
            TestCase.fail("missing final messages not noticed");
        }
        catch (TranscriptVerificationException e)
        {
            TestCase.assertEquals("Initial transcript incomplete 10 messages missing.", e.getMessage());
        }
    }

    @Test
    public void testInsufficientFinall()
        throws Exception
    {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encKey);
        ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(witnessTranscript), new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(getSequence(finalTranscript, new MessageChooser()
        {
            @Override
            public boolean chooseMessage(int index)
            {
                if (index % 2 == 0)
                {
                    return false;
                }

                return true;
            }
        })));

        try
        {
            verifier.verify();
            TestCase.fail("missing final messages not noticed");
        }
        catch (TranscriptVerificationException e)
        {
            TestCase.assertEquals("Final transcript incomplete 10 messages missing.", e.getMessage());
        }
    }

    @Test
    public void testSampleWitnesses()
        throws Exception
    {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encKey);
        ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(getSequence(witnessTranscript, new MessageChooser()
        {
            @Override
            public boolean chooseMessage(int index)
            {
                if (index % 2 == 0)
                {
                    return false;
                }

                return true;
            }
        })), new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(finalTranscript));

        verifier.verify();
    }

    @Test
    public void testCorruptWitnesses()
        throws Exception
    {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(encKey);
        try
        {
            ECShuffledTranscriptVerifier verifier = new ECShuffledTranscriptVerifier(pubKey, new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(initialTranscript), new ByteArrayInputStream(finalTranscript));

            TestCase.fail("corrupt messages not noticed");
        }
        catch (IOException e)
        {
            TestCase.assertEquals("Unable to parse transcripts: illegal object in getInstance: org.bouncycastle.asn1.DLSequence", e.getMessage());
        }
    }

    private byte[] getSequence(byte[] init, MessageChooser chooser)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(init);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        ASN1Primitive obj;

        int count = 0;
        while ((obj = aIn.readObject()) != null)
        {
            if (chooser.chooseMessage(count++))
            {
                dOut.writeObject(obj);
            }
        }

        dOut.close();

        return bOut.toByteArray();
    }
}
