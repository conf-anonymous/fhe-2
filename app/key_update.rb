module X
  class KeyUpdate

    def self.generate(x, k)
      if k.nil?
        k2_ = X::FHE.random_number(x.p2.bit_length / 4)
        k2 = X::FHE.hensel_packing(k2_,x.p2,x.p3,x.p4,x.q)

        x.t1 = k2.gp(x.k1.inverse)
        x.t2 = x.k1.gp(k2.inverse)

        x.k1 = k2
      else
        x.t1 = k.gp(x.k1.inverse)
        x.t2 = x.k1.gp(k.inverse)

        x.k1 = k
      end

      x
    end

    def self.update(c,x)
      c = x.t1.gp(c).gp(x.t2)

      c
    end

  end
end
