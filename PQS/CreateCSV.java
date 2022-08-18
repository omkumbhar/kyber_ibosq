import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.openquantumsafe.*;

import com.opencsv.CSVWriter;

public class CreateCSV{

    public static ArrayList<String> supported_KEMs = new ArrayList<>();
    public static ArrayList<Parameters> all_computed = new ArrayList<>();
    public static void main(String[] args) {
        // Classic-McEliece
        // supported_KEMs.add("Classic-McEliece-348864");
        // supported_KEMs.add("Classic-McEliece-348864f");
        // supported_KEMs.add("Classic-McEliece-460896");
        // supported_KEMs.add("Classic-McEliece-460896f");
        // supported_KEMs.add("Classic-McEliece-6688128");
        // supported_KEMs.add("Classic-McEliece-6688128f");
        // supported_KEMs.add("Classic-McEliece-6960119");
        // supported_KEMs.add("Classic-McEliece-6960119f");
        supported_KEMs.add("Classic-McEliece-8192128");
        // supported_KEMs.add("Classic-McEliece-8192128f");


        // Kyber     
        // supported_KEMs.add("Kyber512");
        // supported_KEMs.add("Kyber512-90s");
        // supported_KEMs.add("Kyber768");
        // supported_KEMs.add("Kyber768-90s");
        supported_KEMs.add("Kyber1024");
        // supported_KEMs.add("Kyber1024-90s");

        // NTRU
        // supported_KEMs.add("NTRU-HPS-2048-509");
        // supported_KEMs.add("NTRU-HPS-2048-677");
        // supported_KEMs.add("NTRU-HRSS-701");
        // supported_KEMs.add("NTRU-HPS-4096-821");
        // supported_KEMs.add("NTRU-HPS-4096-1229");
        supported_KEMs.add("NTRU-HRSS-1373");
        
        //SABER
        // supported_KEMs.add("LightSaber-KEM");
        // supported_KEMs.add("Saber-KEM");
        supported_KEMs.add("FireSaber-KEM");
        
     


        for(String kem : supported_KEMs){
            PerformKEM  kems = new PerformKEM(kem);
            

            Parameters perm = new Parameters();
            perm.method_name  = kem;
            
            if(!kem.contains("Classic-McEliece")) {
                perm.keypairGenTime = kems.generateKeypairTime();
                perm.encryptingTime = kems.encryptTime();
                perm.DecryptingTime = kems.DecryptingTime();
            }


            perm.length_secret_key = kems.getSecretKeyLength();
            perm.length_public_key = kems.getPublicKeyLength();
            perm.length_ciphertext = kems.getCipherTextLength();
            perm.nist_level = kems.getNistLevel();

            


            all_computed.add(perm);
            // kems.dispose();

        }


        // for( Parameters p : all_computed ){
        //     System.out.println("#######################################################################");
        //     System.out.println("method_name = " + p.method_name );
        //     System.out.println("keypairGenTime = " + p.keypairGenTime );
        //     System.out.println("encryptingTime = " + p.encryptingTime );
        //     System.out.println("decryptingTime = " + p.DecryptingTime );
        //     System.out.println("public_key length = " + p.length_public_key );
        //     System.out.println("secret_key length = " + p.length_secret_key );
        //     System.out.println("ciphertext length= " + p.length_ciphertext );
        // }
        generateCSV();

    }


    public static void generateCSV(){
        try {
            FileWriter outputfile = new FileWriter("/mnt/d/ky/PQS/benchmarks.csv");

            CSVWriter writer = new CSVWriter(outputfile, ',',
                                         CSVWriter.NO_QUOTE_CHARACTER,
                                         CSVWriter.DEFAULT_ESCAPE_CHARACTER,
                                         CSVWriter.DEFAULT_LINE_END);
            
            List<String[]> data = new ArrayList<String[]>();                       

            data.add(new String[] { "KEM_name", "public_key", "secret_key", "ciphertext","NIST_level", "keygen/s", "encaps/s", "decaps/s" });
            for (Parameters p : all_computed  ){
                data.add(new String[] { p.method_name, 
                                        String.valueOf(p.length_public_key), 
                                        String.valueOf(p.length_secret_key), 
                                        String.valueOf(p.length_ciphertext),
                                        p.nist_level,
                                        String.valueOf( p.keypairGenTime),
                                        String.valueOf( p.encryptingTime),
                                        String.valueOf( p.DecryptingTime)
                                        });
            }
            
            // System.out.println( "Size of the data " + data.size() );

            // for (  int i= 0; i < data.size(); i++ ){

            //     System.out.println( data.get(0)[0] );
            // }


            writer.writeAll(data);
            writer.close();

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}