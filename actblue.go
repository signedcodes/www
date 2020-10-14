package main

type Fundraise struct {
	Name          string
	Slug          string
	USCitizenOnly bool
}

var Fundraises = []Fundraise{
	{Name: "Biden/Harris", Slug: "biden-harris", USCitizenOnly: true},
	{Name: "US Senate", Slug: "senate", USCitizenOnly: true},
	{Name: "US House", Slug: "house", USCitizenOnly: true},

	{Name: "RAICES", Slug: "raices", USCitizenOnly: false},
	{Name: "Democracy Docket", Slug: "democracy-docket", USCitizenOnly: false},
}

var FundraiseForSlug map[string]Fundraise

func init() {
	FundraiseForSlug = make(map[string]Fundraise)
	for _, f := range Fundraises {
		FundraiseForSlug[f.Slug] = f
	}
}
