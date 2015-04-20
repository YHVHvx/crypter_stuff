package net.c0fe.experiments.reflection.sample;

/**
 * User: kostapc
 */

public class Print5Digits {

    private int[] digits;

    private Print5Digits() {
        digits = new int[] {4,9,4,0,6};
    }

    @Override
    public String toString() {
        String out = "[";
        for(int zzz : digits) {
            out+=zzz;
        }
        out += "]";
        return out;
    }

    public static void main(String[] argc) {
        Print5Digits p5d = new Print5Digits();
        System.out.println("yeah, this is "+p5d);
    }
}
