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

public class TokenCreation {
    
    public static GSSCredential createCredential(Oid mechOid, String userName) throws GSSException 
    {

        GSSCredential clientGssCreds = null;
        GSSManager manager = GSSManager.getInstance();
        
        GSSName gssUserName = manager.createName(
                userName, 
                GSSName.NT_USER_NAME, 
                mechOid);

        clientGssCreds = manager.createCredential(
                gssUserName.canonicalize(mechOid),
                GSSCredential.INDEFINITE_LIFETIME, 
                mechOid,
                GSSCredential.INITIATE_ONLY);

        return clientGssCreds;
    }
    
    /**
     * 
     * @param sUserName
     * @param sServerSpn
     * @param sTokenType
     * @return
     * @throws IOException 
     * @throws IllegalArgumentException 
     * @throws ArrayIndexOutOfBoundsException 
     * @throws GSSException 
     */
    public static void createToken(String sUserName, String sServerSpn, String sTokenType) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, IOException, GSSException
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
            GSSCredential gsscredential = createCredential(mechOid, sUserName);
            
            if (gsscredential != null) {
                byte[] token = createToken(gsscredential, sServerSpn, mechOid);
                
                if (token != null) {
                    outputToken(token, sTokenType);
                }
            }
        }
        
    }

    public static byte[] createToken(GSSCredential clientGssCreds, 
            String sServerSpn, Oid mechOid) throws GSSException 
    {
        byte[] token = new byte[0];
        GSSManager manager = GSSManager.getInstance();

        // create target server SPN
        GSSName gssServerName = manager.createName(
                sServerSpn,
                GSSName.NT_USER_NAME);

        GSSContext clientContext = manager.createContext(
                gssServerName.canonicalize(mechOid), 
                mechOid,
                clientGssCreds, 
                GSSContext.DEFAULT_LIFETIME);

        // optional enable GSS credential delegation
        clientContext.requestCredDeleg(true);

        // create a SPNEGO token for the target server
        token = clientContext.initSecContext(token, 0, token.length);

        return token;
    }

    
    public static void outputToken(byte[] token, String sType) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, IOException
    {
        if (token != null) {
            System.out.println("Tokenth = " + token.length);
            
            Base64 base64 = new Base64();

            //HexDump.dump(token, 0, System.out, 0);

            FileUtil.writeByte2File(token, sType + "_token.bin");
            System.out.println("\n\nToken [" + sType + "_token.bin] was created");

            String encodedToken2 = base64.encodeToString(token);
            FileUtil.writeByte2File(encodedToken2.getBytes(), sType + "_token_64.txt");
            System.out.println("\n\nToken [" + sType + "_token_64.txt] was created");

            String encodedToken = base64.encodeBase64String(token);
            System.out.println("Token64 = \n" + encodedToken);
        }        
    }

/*
	private static final String getHexBytes(byte[] bytes, int pos, int len) 
    {
        StringBuffer sb = new StringBuffer();
        for (int i = pos; i >4) & 0x0f;
            int b2 = bytes[i] & 0x0f;

            sb.append(Integer.toHexString(b1));
            sb.append(Integer.toHexString(b2));
            sb.append(' ');
        }
        return sb.toString();
        }

        private static final String getHexBytes(byte[] bytes) {
        return getHexBytes(bytes, 0, bytes.length);
    }
 */
    
    /**
     * @param args
     */
    public static void main(String[] args) 
    {
        
    	Options options = new Options();
    	options.addOption("s", "serverprincipal", true, "server principal");
    	options.addOption("c", "clientprincipal", true, "client principal");
    	options.addOption("t", "type", true, "Ticket type (krb5 or spnego");
    	options.addOption("j", "jaasfile", true, "Jaas file");
    	options.addOption("f", "useSubjectCredsOnly", true, "Set useSubjectCredsOnly");
    	options.addOption("64", false, "Create base64 version");
    	
    	CommandLineParser parser = new DefaultParser();
    	HelpFormatter formatter = new HelpFormatter();

        try {
			CommandLine cmd = parser.parse( options, args);
			String sServerSpn = cmd.getOptionValue("s");
			String sClientSpn = cmd.getOptionValue("c");
			String ttype = cmd.getOptionValue("t");
			String jaasFile = cmd.getOptionValue("j","bcsLogin.conf");
			String usco = cmd.getOptionValue("f","false");
			
	        System.setProperty("javax.security.auth.useSubjectCredsOnly", usco);
	        System.setProperty("java.security.debug","gssloginconfig,logincontext,configfile,configparser");
	        System.setProperty("java.security.auth.login.config", jaasFile);

    	
	        if (!("krb5".equals(ttype) || "spnego".equals(ttype))) {
				formatter.printHelp("TokenCreation",options);
	        } else {
					TokenCreation.createToken(sClientSpn, sServerSpn, ttype);
            }
        } catch (ParseException e) {
			System.err.println( "Parsing failed.  Reason: " + e.getMessage() );
			formatter.printHelp("TokenCreation",options);
		} catch (ArrayIndexOutOfBoundsException | IllegalArgumentException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GSSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}
