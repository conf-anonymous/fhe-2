module X
  class KeyExchange

    def self.party_identification(x)
      pr_ = X::FHE.random_number(x.p2.bit_length / 4)
      pu_ = X::FHE.random_number(x.p2.bit_length / 4)

      pr = X::FHE.hensel_packing(pr_,x.p2,x.p3,x.p4,x.q)
      pu = X::FHE.hensel_packing(pu_,x.p2,x.p3,x.p4,x.q)

      [pr,pu]
    end

    def self.public_communication_identifier(pu1,pu2)
      g = pu1.gp(pu2)
    end

    def self.subkey(pr,g,i)
      if i == 1
        subk = pr.gp(g)
      elsif i == 2
        subk = g.gp(pr)
      end

      subk
    end

    def self.exchange(subk,pr,g,i)
      if i == 1
        k = pr.gp(subk).gp(g).add(g)
      elsif i == 2
        k = subk.gp(pr).gp(g).add(g)
      end

      k
    end

  end
end
