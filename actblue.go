package main

type Fundraise struct {
	Name          string
	Slug          string
	USCitizenOnly bool
}

var Fundraises = []Fundraise{
	{Name: "Biden/Harris", Slug: "signed-codes-biden-harris", USCitizenOnly: true},
	{Name: "US Senate", Slug: "signed-codes-senate", USCitizenOnly: true},
	{Name: "US House", Slug: "signed-codes-house", USCitizenOnly: true},

	{Name: "RAICES", Slug: "signed-codes-raices", USCitizenOnly: false},
}

var FundraiseForSlug map[string]Fundraise

func init() {
	FundraiseForSlug = make(map[string]Fundraise)
	for _, f := range Fundraises {
		FundraiseForSlug[f.Slug] = f
	}
}
