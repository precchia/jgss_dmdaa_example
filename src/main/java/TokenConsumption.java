import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import java.io.IOException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.HexDump; 


/**
 * @author Allen
 *
 */
public class TokenConsumption {
    
    public static void consumeToken(byte[] token, String sTokenType) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, IOException, GSSException
    {
        Oid mechOid = null; 
        if (sTokenType.compareTo("krb5") == 0) {
            mechOid = new Oid("1.2.840.113554.1.2.2");                
        } else {
            if (sTokenType.compareTo("spnego") == 0) {
                mechOid = new Oid("1.3.6.1.5.5.2");
            } else {
                System.out.println("Token [" + sTokenType + "] was not supported.");
                System.out.println("Usagea TokenCreation krb5 | spnego");                
            }
        }
        if (mechOid != null) {
            consumeToken(token, mechOid);
        }
    }

    
    public static void consumeToken(byte[] token, Oid mechOid) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, IOException, GSSException
    {
        String endpointSPN = null;

        GSSManager manager = GSSManager.getInstance();

        //first obtain it's own credentials...
        GSSCredential myCred = manager.createCredential(null, 
              GSSCredential.DEFAULT_LIFETIME, 
              mechOid, 
              GSSCredential.ACCEPT_ONLY);
      
        //...and create a context for this credentials...
        GSSContext context = manager.createContext(myCred);

        //...then use that context to authenticate the calling peer by reading his token          
        byte[] tokenForPeer = context.acceptSecContext(token, 0, token.length);

        if (!context.isEstablished()) {
          System.out.println("Contextnot established!");
          return;
      }
      
      if (tokenForPeer != null) {
          System.out.println("there token to send back to the peer, but I leave this out for now");
          HexDump.dump(tokenForPeer, 0, System.out, 0);
      }

      //...then obtain information from the context
      System.out.println("Client Principal is " + context.getSrcName());
      System.out.println("Server Principal is " + context.getTargName());
      
      if (context.getCredDelegState()) {
          System.out.println("Then is delegatable.");              
      } else {
          System.out.println("Then is NOT delegatable");              
      }
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
    	Options options = new Options();
    	options.addOption("t", "type", true, "Ticket type (krb5 or spnego)");
    	options.addOption("64", false, "Read base64 version");
    	options.addOption("j", "jaasfile", true, "Jaas file");
    	
    	CommandLineParser parser = new DefaultParser();
    	HelpFormatter formatter = new HelpFormatter();

        String ttype;
        String jaasFile;
        
        try {
			CommandLine cmd = parser.parse( options, args);
			ttype = cmd.getOptionValue("t");
			jaasFile = cmd.getOptionValue("j","bcsLogin.conf");
			
	        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
	        System.setProperty("java.security.debug","gssloginconfig,logincontext,configfile,configparser");
	        System.setProperty("java.security.auth.login.config", jaasFile);

	        if (!("krb5".equals(ttype) || "spnego".equals(ttype))) {
				formatter.printHelp("TokenCreation",options);
	        } else {
                if (cmd.hasOption("64")) {                    
                    System.out.println("Token file [" + ttype + "_token_64.txt] will be consumed *** ");
                    byte[] token64 = FileUtil.readByteFromFile(ttype + "_token_64.txt");
                    byte[] token = Base64.decodeBase64(token64);
                    TokenConsumption.consumeToken(token, ttype);
	            } else {
	                // process normal token from the file
	                System.out.println("Token file [" + ttype + "_token.bin] will be consumed *** ");
	                byte[] token = FileUtil.readByteFromFile(ttype + "_token.bin");
	                TokenConsumption.consumeToken(token, ttype);                    
	            }
        	}
		} catch (ParseException e) {
			System.err.println( "Parsing failed.  Reason: " + e.getMessage() );
			formatter.printHelp("TokenCreation",options);
		}
    	catch (Exception e) {
        	e.printStackTrace();
        }
    }
}
