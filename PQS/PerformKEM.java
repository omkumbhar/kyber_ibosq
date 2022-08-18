import org.openquantumsafe.*;

public class PerformKEM {
    public String kem_name;
    private KeyEncapsulation client;
    private KeyEncapsulation server;
    public byte[] client_public_key;
    public Pair<byte[], byte[]> server_pair;
    PerformKEM(String kem){
        this.kem_name = kem;
        client = new KeyEncapsulation(this.kem_name);
        client.print_details();
    }


    public long generateKeypairTime(){
        long t = System.currentTimeMillis();
        client_public_key = client.generate_keypair();
        long timeElapsed = System.currentTimeMillis() - t;
        
        return timeElapsed;
    }

    public long encryptTime(){
        server = new KeyEncapsulation(this.kem_name);
        long t = System.currentTimeMillis();
        server_pair = server.encap_secret(client_public_key);
        // System.out.println("It took " + (System.currentTimeMillis() - t) + " millisecs to encapsulate the secret.");
        return System.currentTimeMillis() - t;
    }

    
    public long DecryptingTime(){
        byte[] ciphertext = server_pair.getLeft();
        long t = System.currentTimeMillis();
        byte[] shared_secret_client = client.decap_secret(ciphertext);
        // System.out.println("It took " + (System.currentTimeMillis() - t) + " millisecs to decapsulate the secret.");
        return System.currentTimeMillis() - t;
    }

    public long getPublicKeyLength() {
        return client.getCipherTextLength();
    }
    public long getSecretKeyLength() {
        return client.getSecretKeyLength();
    }
    public long getCipherTextLength() {
        return client.getCipherTextLength();
    }

    public String getNistLevel(){
        return client.getNistLevel();
    }

    public void  dispose(){
        client.dispose_KEM();
        server.dispose_KEM();
    }

}
