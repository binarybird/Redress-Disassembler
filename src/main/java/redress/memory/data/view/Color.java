package redress.memory.data.view;

/**
 * Created by jamesrichardson on 2/29/16.
 */
public class Color{
    private int red = 104;
    private int green = 255;
    private int blue = 0;
    private double alpha = 0.43;

    private Color(int r,int b, int g,double a){
        red=r;
        blue=b;
        green=g;
        alpha=a;
    }

    private Color(){

    }

    public static Color rgba(int r,int b,int g,double a){
        return new Color(r,b,g,a);
    }

    public static Color rgba(){
        return new Color();
    }

    public int getRed(){
        return red;
    }
    public int getGreen(){
        return green;
    }
    public int getBlue(){
        return blue;
    }
    public double getAlpha(){
        return alpha;
    }
    @Override
    public String toString(){
        return "rgba("+red+","+green+","+blue+","+alpha+");";
    }
}
