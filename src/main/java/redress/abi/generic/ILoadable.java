package redress.abi.generic;


/**
 * Created by jamesrichardson on 2/23/16.
 */
public interface ILoadable{
    public void setLoader(ILoader loader);
    public ILoader getLoader();
}
