import java.util.ArrayList;
import java.util.List;

/**
 * Created by jamesrichardson on 1/11/16.
 */
public class JSONParser {

    public class JSONData{
        public String data;
    }

    public class JSON<T extends JSONData> extends ArrayList<T> {
        private T Data = null;
        private boolean valueIsArray = false;

        public T getKey(){
            return Data;
        }
        public void setKey(T in){
            Data = in;
        }
    }


    public JSON parse(String in){
        JSON ret = new JSON();



        return ret;
    }

    int currentLocation;

    private JSON parse(JSON current, int location,char[] input){

        final char c = input[location];

        if(input.length > location) {

            switch (c) {
                case '{':
                    break;
                case '}':
                    break;
                case ',':
                    break;
                case ':':
                    break;
                default:
                    JSONData currentData = new JSONData();
                    parseData(currentData,location,input);

                    break;
            }
        }else{
            return current;
        }
        return parse(current,location++,input);

    }

    private JSONData parseData(JSONData current, int location, char[] input){

            switch (input[location]) {
                case '{': return current;
                case '}':return current;
                case ',':return current;
                case ':':return current;
                default: current.data+=current;break;
            }
        return parseData(current, location++,input);

    }


}
